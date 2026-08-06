"""Isolated browser renderer for safe web page analysis."""

from dataclasses import dataclass

from shared.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RenderResult:
    """Result of rendering a web page."""
    
    final_url: str
    title: str
    html: str
    screenshot: bytes
    redirects: list[str]
    forms: list[dict] | None = None
    javascript_detected: bool = False


async def render_page(
    url: str,
    timeout_ms: int = 15000,
    viewport_width: int = 1280,
    viewport_height: int = 900,
    max_redirects: int = 10,
) -> RenderResult:
    """
    Render a web page in an isolated browser context.
    
    Security measures:
    - No extensions
    - No sync/background networking
    - No downloads
    - Isolated context (no cookies persistence)
    - Timeout limits
    - Size limits on HTML
    
    Args:
        url: URL to render (must be pre-validated)
        timeout_ms: Navigation timeout in milliseconds
        viewport_width: Browser viewport width
        viewport_height: Browser viewport height
        max_redirects: Maximum number of redirects to track
        
    Returns:
        RenderResult with page content and metadata
        
    Raises:
        ValueError: If page is too large or other validation fails
        TimeoutError: If page takes too long to load
    """
    from playwright.async_api import async_playwright
    
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-sync",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-plugins",
                "--no-first-run",
            ],
        )
        
        context = await browser.new_context(
            accept_downloads=False,
            java_script_enabled=True,  # Needed for modern sites
            ignore_https_errors=False,  # Don't ignore cert errors
            viewport={"width": viewport_width, "height": viewport_height},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        
        redirects: list[str] = []
        forms: list[dict] = []
        javascript_detected = False
        
        async def inspect_request(request):
            """Track navigation requests for redirect detection."""
            nonlocal javascript_detected
            
            if request.is_navigation_request():
                redirects.append(request.url)
                
                # Limit redirects
                if len(redirects) > max_redirects:
                    logger.warning(
                        "too_many_redirects",
                        url=url,
                        redirect_count=len(redirects),
                    )
            
            # Detect JavaScript usage
            if request.resource_type == "script":
                javascript_detected = True
        
        page = await context.new_page()
        page.on("request", inspect_request)
        
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            
            if response is None:
                raise ValueError("Failed to load page")
            
            # Get page content
            html = await page.content()
            
            # Size limit check
            if len(html.encode("utf-8")) > 5_000_000:  # 5 MB
                raise ValueError("Page HTML exceeds size limit (5MB)")
            
            # Get title
            title = await page.title()
            
            # Take screenshot
            screenshot = await page.screenshot(
                type="png",
                full_page=False,
            )
            
            # Detect forms (potential credential harvesting)
            forms = await _detect_forms(page)
            
            return RenderResult(
                final_url=page.url,
                title=title or "",
                html=html,
                screenshot=screenshot,
                redirects=redirects[:max_redirects],
                forms=forms,
                javascript_detected=javascript_detected,
            )
            
        finally:
            await context.close()
            await browser.close()


async def _detect_forms(page) -> list[dict]:
    """Detect forms on the page that might harvest credentials."""
    try:
        forms = await page.evaluate("""
            () => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map(form => ({
                    action: form.action || 'self',
                    method: form.method || 'GET',
                    inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                        type: input.type,
                        name: input.name,
                        placeholder: input.placeholder,
                        autocomplete: input.autocomplete,
                    })),
                }));
            }
        """)
        
        # Filter for suspicious forms (password fields, email fields, etc.)
        suspicious_forms = []
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("type") in ("password", "email", "tel"):
                    suspicious_forms.append(form)
                    break
        
        return suspicious_forms
        
    except Exception as e:
        logger.error("form_detection_error", error=str(e))
        return []
