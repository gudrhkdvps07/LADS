import os


def pause_if_enabled() -> None:
    """Set PAUSE_ON_EXIT=1 to keep the terminal open."""

    # .env에 PAUSE_ON_EXIT=1을 넣어도 동작하게
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass

    if os.getenv("PAUSE_ON_EXIT") == "1":
        try:
            input("\n[PAUSE_ON_EXIT] Enter를 누르면 종료합니다...")
        except EOFError:
            pass

