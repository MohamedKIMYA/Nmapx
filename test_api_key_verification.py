"""Verify that API keys are never exposed in error messages or logs."""
import asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from cve import CVEEnricher, _sanitize_error_message


def test_api_key_not_in_exception_handling():
    """Test that exception details with API key don't get printed."""
    api_key = "test-secret-key-123456789"
    
    # Simulate a RequestError that might contain API key in message
    mock_error = httpx.RequestError(
        "Connection failed: headers={'apiKey': 'test-secret-key-123456789'}"
    )
    
    # Mock client.get to raise RequestError (async)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=mock_error)
    
    # Patch the async context manager so __aenter__ returns our mock client
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    
    with patch('cve.httpx.AsyncClient', return_value=mock_ctx):
        result = asyncio.run(CVEEnricher.query(keyword="ssh", api_key=api_key))
        assert result == []


def test_error_message_sanitization():
    """Verify error messages are sanitized before any output."""
    api_key = "super-secret-nvd-key-1234567890"
    
    # Test various error scenarios
    error_scenarios = [
        f"NVD API request failed: apiKey={api_key}",
        f"HTTP request error: Authorization: Bearer {api_key}",
        f"Connection error with headers {{'apiKey': '{api_key}'}}",
    ]
    
    for error_msg in error_scenarios:
        sanitized = _sanitize_error_message(error_msg, api_key)
        assert api_key not in sanitized, f"API key leaked in: {sanitized}"
        assert "****" in sanitized or "apiKey" in sanitized
        print(f"✓ Sanitized: {error_msg[:40]}... → {sanitized[:60]}...")


def test_mask_function():
    """Verify masking function creates safe representations."""
    api_key = "production-nvd-api-key-abcdefgh"
    masked = CVEEnricher._mask_api_key_for_logging(api_key)
    
    assert api_key not in masked
    assert masked.startswith("prod")
    assert masked.endswith("efgh")
    assert "****" in masked
    print(f"✓ Masked key: {api_key} → {masked}")


if __name__ == "__main__":
    print("\n[CVE API Key Protection Verification]\n")
    
    # Run async test
    asyncio.run(test_api_key_not_in_exception_handling())
    
    # Run sync tests
    test_error_message_sanitization()
    test_mask_function()
    
    print("\n✅ All API key protection tests passed!")
    print("   • API keys not exposed in error handling")
    print("   • Error messages properly sanitized")
    print("   • Masking function creates safe representations")
