function toggleMenu(force) {
  var shell = document.getElementById('app-shell') || document.body
  var backdrop = document.getElementById('sidebar-backdrop')
  if (!shell) return
  var isOpen = shell.classList.contains('sidebar-open')
  var shouldOpen = force === true ? true : force === false ? false : !isOpen
  shell.classList.toggle('sidebar-open', shouldOpen)
  try {
    localStorage.setItem('lads-sidebar-open', shouldOpen ? '1' : '0')
  } catch (e) {}
  syncMenuBackdrop()
}

function syncMenuBackdrop() {
  var shell = document.getElementById('app-shell') || document.body
  var backdrop = document.getElementById('sidebar-backdrop')
  if (!shell || !backdrop) return
  var showBackdrop =
    shell.classList.contains('sidebar-open') && window.innerWidth < 768
  if (showBackdrop) {
    backdrop.classList.add('is-visible')
  } else {
    backdrop.classList.remove('is-visible')
  }
}

function setSidebarWidth(width) {
  var shell = document.getElementById('app-shell') || document.body
  if (!shell) return
  var min = 150
  var max = Math.min(440, Math.max(260, window.innerWidth - 360))
  var next = Math.max(min, Math.min(max, width))
  shell.style.setProperty('--sidebar-width', next + 'px')
  shell.classList.toggle('sidebar-compact', next < 210)
  try {
    localStorage.setItem('lads-sidebar-width', String(next))
  } catch (e) {}
}

function initSidebarResize() {
  var resizer = document.getElementById('sidebar-resizer')
  if (!resizer) return
  var saved = null
  try {
    saved = parseInt(localStorage.getItem('lads-sidebar-width'), 10)
  } catch (e) {}
  if (saved && window.innerWidth >= 768) setSidebarWidth(saved)

  resizer.addEventListener('pointerdown', function (event) {
    if (window.innerWidth < 768) return
    event.preventDefault()
    resizer.classList.add('is-resizing')
    document.body.style.cursor = 'ew-resize'
    document.body.style.userSelect = 'none'
    if (resizer.setPointerCapture) resizer.setPointerCapture(event.pointerId)

    function move(e) {
      setSidebarWidth(e.clientX)
    }

    function up(e) {
      resizer.classList.remove('is-resizing')
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      if (resizer.releasePointerCapture) {
        try {
          resizer.releasePointerCapture(e.pointerId)
        } catch (err) {}
      }
      document.removeEventListener('pointermove', move)
      document.removeEventListener('pointerup', up)
      document.removeEventListener('pointercancel', up)
    }

    document.addEventListener('pointermove', move)
    document.addEventListener('pointerup', up)
    document.addEventListener('pointercancel', up)
  })
}

var _es = null
var _currentTask = null
var _currentStageTask = null
var _hadError = false

var _labels = {
  crawl: '크롤링',
  payload: '페이로드 준비',
  probe: '주입 테스트 준비',
  execute: '활성 스캔',
  validate: '결과 분석',
  misconfig: '설정 오류 점검',
  bac: '접근제어 점검',
  all: '취약점 스캔',
}

var _taskOrder = [
  'crawl',
  'payload',
  'probe',
  'execute',
  'validate',
  'misconfig',
]

var _stageLabelToTask = {
  CRAWL: 'crawl',
  PAYLOAD: 'payload',
  PROBE: 'probe',
  EXEC: 'execute',
  VALIDATE: 'validate',
  MISCONFIG: 'misconfig',
}

function startFullScan() {
  _startStream('/stream/all')
}

function startScanSkipCrawl() {
  _startStream('/stream/all?skip_crawl=1')
}

function _setButtons(disabled) {
  document.querySelectorAll('button').forEach(function (btn) {
    if (btn.hasAttribute('data-menu-toggle')) return
    btn.disabled = disabled
  })
}

function _badgeClass(kind) {
  if (kind === 'ok') {
    return 'inline-flex items-center gap-2 rounded bg-emerald-50 px-2 py-1 font-mono text-[12px] uppercase text-emerald-700'
  }
  if (kind === 'error') {
    return 'inline-flex items-center gap-2 rounded bg-red-50 px-2 py-1 font-mono text-[12px] uppercase text-red-700'
  }
  return 'inline-flex items-center gap-2 rounded bg-amber-50 px-2 py-1 font-mono text-[12px] uppercase text-amber-700'
}

function _stageFromMessage(message) {
  var text = message.toLowerCase()
  if (
    text.indexOf('[crawl]') !== -1 ||
    text.indexOf('크롤') !== -1 ||
    text.indexOf('crawler') !== -1
  ) {
    return { label: 'CRAWL', cls: 'bg-sky-100 text-sky-800', row: 'bg-sky-50' }
  }
  if (
    text.indexOf('[payload]') !== -1 ||
    text.indexOf('페이로드') !== -1 ||
    text.indexOf('llm') !== -1
  ) {
    return {
      label: 'PAYLOAD',
      cls: 'bg-violet-100 text-violet-800',
      row: 'bg-violet-50',
    }
  }
  if (text.indexOf('[probe]') !== -1 || text.indexOf('주입 테스트') !== -1) {
    return {
      label: 'PROBE',
      cls: 'bg-amber-100 text-amber-800',
      row: 'bg-amber-50',
    }
  }
  if (text.indexOf('[exec]') !== -1 || text.indexOf('실행') !== -1) {
    return {
      label: 'EXEC',
      cls: 'bg-indigo-100 text-indigo-800',
      row: 'bg-indigo-50',
    }
  }
  if (
    text.indexOf('[validate]') !== -1 ||
    text.indexOf('판정') !== -1 ||
    text.indexOf('취약') !== -1
  ) {
    return {
      label: 'VALIDATE',
      cls: 'bg-rose-100 text-rose-800',
      row: 'bg-rose-50',
    }
  }
  if (text.indexOf('[misconfig]') !== -1 || text.indexOf('설정 오류') !== -1) {
    return {
      label: 'MISCONFIG',
      cls: 'bg-blue-100 text-blue-800',
      row: 'bg-blue-50',
    }
  }
  if (
    text.indexOf('[bac]') !== -1 ||
    text.indexOf('vertical') !== -1 ||
    text.indexOf('권한 상승') !== -1
  ) {
    return {
      label: 'BAC',
      cls: 'bg-orange-100 text-orange-800',
      row: 'bg-orange-50',
    }
  }
  return { label: 'SYSTEM', cls: 'bg-slate-100 text-slate-700', row: '' }
}

function _updateProgressBar(percent) {
  percent = Math.max(0, Math.min(100, percent))
  var percentLabel = document.getElementById('pipeline-percent')
  var bar = document.getElementById('pipeline-progress-bar')
  if (percentLabel) percentLabel.textContent = percent + '%'
  if (bar) {
    bar.style.width = percent + '%'
    bar.className =
      percent >= 100
        ? 'h-full rounded-full bg-emerald-500 transition-all duration-500'
        : 'h-full rounded-full bg-amber-500 transition-all duration-300'
  }
}

function _updatePipelineCardForStage(stageLabel) {
  var taskKey = _stageLabelToTask[stageLabel]
  if (!taskKey || taskKey === _currentStageTask) return
  _currentStageTask = taskKey

  var steps = document.querySelectorAll('.pipeline-step-card')
  var targetIdx = _taskOrder.indexOf(taskKey)

  steps.forEach(function (step) {
    var stepTask = step.dataset.task
    var stepIdx = _taskOrder.indexOf(stepTask)
    var node = step.querySelector('.pipeline-node')
    var status = step.querySelector('.pipeline-status')
    var icon = node ? node.querySelector('.material-symbols-outlined') : null
    if (!node || !status) return

    if (stepIdx < targetIdx) {
      step.className = 'pipeline-step-card complete'
      node.className = 'pipeline-node'
      if (icon) icon.textContent = 'check'
      status.textContent = 'Done'
      status.className = 'pipeline-status'
    } else if (stepTask === taskKey) {
      step.className = 'pipeline-step-card active'
      node.className = 'pipeline-node animate-pulse'
      status.textContent = 'Running'
      status.className = 'pipeline-status text-amber-600'
    }
  })
}

function _resetPipelineCards() {
  document.querySelectorAll('.pipeline-step-card').forEach(function (card) {
    card.className = 'pipeline-step-card pending'
    var icon = card.querySelector('.pipeline-node .material-symbols-outlined')
    var status = card.querySelector('.pipeline-status')
    if (icon) icon.textContent = card.dataset.icon || 'circle'
    if (status) {
      status.textContent = 'Waiting'
      status.className = 'pipeline-status'
    }
  })
}

function _startStream(url) {
  if (_es) {
    _es.close()
    _es = null
  }

  var logArea = document.getElementById('log-area')
  var logTitle = document.getElementById('log-title')
  var logBadge = document.getElementById('log-badge')
  if (!logArea || !logTitle || !logBadge) return

  var taskName = url.split('/stream/')[1].split('?')[0]
  _currentTask = taskName
  _currentStageTask = null
  _hadError = false

  logTitle.textContent = (_labels[taskName] || taskName) + ' 로그'
  logBadge.textContent = 'Running'
  logBadge.className = _badgeClass('running')
  logArea.textContent = ''
  _setButtons(true)
  _updateProgressBar(0)
  if (taskName === 'all') _resetPipelineCards()

  _es = new EventSource(url)

  _es.onmessage = function (event) {
    if (event.data === '__DONE__') {
      _es.close()
      _es = null
      if (_hadError) {
        logBadge.textContent = 'Error'
        logBadge.className = _badgeClass('error')
      } else {
        logBadge.textContent = 'Done'
        logBadge.className = _badgeClass('ok')
        _updateProgressBar(100)
      }
      _setButtons(false)
      if (!_hadError) {
        setTimeout(function () {
          if (_currentTask === 'all') {
            fetch('/api/status').then(function(r){ return r.json(); }).then(function(s){
              window.location.href = s.run_id ? '/runs/' + s.run_id : '/runs'
            }).catch(function(){ window.location.href = '/runs' })
          } else {
            location.reload()
          }
        }, 1500)
      }
      return
    }

    if (event.data.startsWith('__PROGRESS__')) {
      var pct = parseInt(event.data.replace('__PROGRESS__', ''), 10)
      _updateProgressBar(pct)
      return
    }

    var stage = _stageFromMessage(event.data)

    if (_currentTask === 'all' && _stageLabelToTask[stage.label]) {
      _updatePipelineCardForStage(stage.label)
    }

    var row = document.createElement('div')
    row.className = 'flex gap-4 rounded px-2 py-1 ' + stage.row

    var time = document.createElement('span')
    time.className = 'w-[70px] shrink-0 text-outline'
    time.textContent = new Date().toLocaleTimeString('ko-KR', { hour12: false })

    var stageBadge = document.createElement('span')
    stageBadge.className =
      'w-[82px] shrink-0 rounded px-2 text-center text-[11px] font-black ' +
      stage.cls
    stageBadge.textContent = stage.label

    var isError = event.data.indexOf('[ERROR]') !== -1
    if (isError) _hadError = true

    var level = document.createElement('span')
    level.className = 'w-[52px] shrink-0 text-secondary'
    level.textContent = isError
      ? '[ERROR]'
      : event.data.indexOf('[WARN]') !== -1
        ? '[WARN]'
        : '[INFO]'

    var message = document.createElement('span')
    message.className = isError ? 'text-error' : 'text-slate-950'
    message.textContent = event.data

    row.appendChild(time)
    row.appendChild(stageBadge)
    row.appendChild(level)
    row.appendChild(message)
    logArea.appendChild(row)
    logArea.scrollTop = logArea.scrollHeight
  }

  _es.onerror = function () {
    if (_es) {
      _es.close()
      _es = null
    }
    logBadge.textContent = 'Error'
    logBadge.className = _badgeClass('error')
    _setButtons(false)
    var row = document.createElement('div')
    row.className = 'text-error'
    row.textContent = '[연결 오류] 서버 상태를 확인하세요.'
    logArea.appendChild(row)
  }
}

// ── 스캔 상태 폴링 (모든 페이지 공통) ─────────────────────────
function _updateScanBadge(status) {
  var badge = document.getElementById('nav-scan-badge')
  var label = document.getElementById('nav-scan-label')
  if (!badge) return
  if (status && status.running) {
    badge.classList.remove('hidden')
    if (label)
      label.textContent = (_labels[status.task] || status.task) + ' 진행 중'
  } else {
    badge.classList.add('hidden')
  }
}

function _pollScanStatus() {
  fetch('/api/status')
    .then(function (r) {
      return r.json()
    })
    .then(function (status) {
      _updateScanBadge(status)

      // 메인 페이지에서 실행 중인데 스트림이 없으면 재연결 (버퍼 로그부터 수신)
      if (status.running && !_es) {
        var logArea = document.getElementById('log-area')
        if (logArea) {
          _currentTask = status.task
          _currentStageTask = null
          _hadError = false
          var logTitle = document.getElementById('log-title')
          var logBadge = document.getElementById('log-badge')
          if (logTitle)
            logTitle.textContent =
              (_labels[status.task] || status.task) + ' 로그'
          if (logBadge) {
            logBadge.textContent = 'Running'
            logBadge.className = _badgeClass('running')
          }
          _setButtons(true)
          _es = new EventSource('/stream/' + status.task)
          _es.onmessage = function (event) {
            if (event.data === '__DONE__') {
              _es.close()
              _es = null
              if (logBadge) {
                logBadge.textContent = 'Done'
                logBadge.className = _badgeClass('ok')
              }
              _setButtons(false)
              setTimeout(function () {
                location.reload()
              }, 1500)
              return
            }
            if (event.data.startsWith('__PROGRESS__')) {
              _updateProgressBar(
                parseInt(event.data.replace('__PROGRESS__', ''), 10),
              )
              return
            }
            var stage = _stageFromMessage(event.data)
            if (_currentTask === 'all' && _stageLabelToTask[stage.label])
              _updatePipelineCardForStage(stage.label)
            var row = document.createElement('div')
            row.className = 'text-slate-500 text-[12px]'
            row.textContent = event.data
            logArea.appendChild(row)
            logArea.scrollTop = logArea.scrollHeight
          }
          _es.onerror = function () {
            if (_es) {
              _es.close()
              _es = null
            }
            _setButtons(false)
          }
        }
      }
    })
    .catch(function () {})
}

// 페이지 로드 시 즉시 확인 + 10초마다 폴링
document.addEventListener('DOMContentLoaded', function () {
  var shell = document.getElementById('app-shell') || document.body
  var saved = null
  try {
    saved = localStorage.getItem('lads-sidebar-open')
  } catch (e) {}
  var shouldOpen = saved === null ? window.innerWidth >= 768 : saved === '1'
  if (shell) shell.classList.toggle('sidebar-open', shouldOpen)
  initSidebarResize()
  syncMenuBackdrop()
  window.addEventListener('resize', function () {
    var savedWidth = null
    try {
      savedWidth = parseInt(localStorage.getItem('lads-sidebar-width'), 10)
    } catch (e) {}
    if (savedWidth && window.innerWidth >= 768) setSidebarWidth(savedWidth)
    syncMenuBackdrop()
  })
  _pollScanStatus()
  setInterval(_pollScanStatus, 10000)
})
