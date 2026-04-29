"""
LLM Client — GPT-4o 전용 모듈
사용법:
    client = LLMClient()
    result = client.generate("프롬프트")
"""

import os
import time
from typing import Optional

from openai import OpenAI


class LLMClient:
    def __init__(
        self,
        model: str = "gpt-4o",                    # OpenAI GPT-4o
        api_key: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ):
        self.model = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.client = OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            # base_url 미지정 → OpenAI 기본 엔드포인트 사용
        )

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
    ) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"  [LLMClient] 시도 {attempt}/{self.max_retries} 실패: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    raise


# ── 직접 실행 시 연결 테스트 ────────────────────────────────────
if __name__ == "__main__":
    client = LLMClient()
    result = client.generate(
        prompt="한 문장으로만 답해주세요: 오늘 날씨가 어때요?",
        system="당신은 친절한 AI입니다.",
    )
    print(f"\n응답: {result}\n")
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
