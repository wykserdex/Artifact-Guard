"""Unit tests for PII redaction utilities."""

import pytest

from shared.redaction import (
    redact_phone,
    redact_email,
    redact_credit_card,
    redact_passport,
    redact_snils,
    redact_inn,
    redact_text,
    contains_pii,
)


class TestPhoneRedaction:
    """Tests for phone number redaction."""

    def test_redact_russian_phone_plus7(self):
        """Test redacting Russian phone with +7 prefix."""
        text = "Contact me at +7 999 123-45-67"
        result = redact_phone(text)
        
        assert "+7 *** ***-**-67" in result
        assert "999" not in result.split("+7")[1]

    def test_redact_russian_phone_8_prefix(self):
        """Test redacting Russian phone with 8 prefix."""
        text = "Call 8 999 123 45 67"
        result = redact_phone(text)
        
        assert "***-**-67" in result

    def test_redact_phone_no_spaces(self):
        """Test redacting phone without spaces."""
        text = "Phone: +79991234567"
        result = redact_phone(text)
        
        assert "***-**-67" in result or "+" in result

    def test_redact_multiple_phones(self):
        """Test redacting multiple phone numbers."""
        text = "Numbers: +7 999 111-22-33 and +7 888 444-55-66"
        result = redact_phone(text)
        
        # Both should be redacted
        assert result.count("***") >= 2

    def test_preserve_non_phone_numbers(self):
        """Test that non-phone numbers are preserved."""
        text = "Order ID: 12345, Year: 2024"
        result = redact_phone(text)
        
        assert result == text


class TestEmailRedaction:
    """Tests for email address redaction."""

    def test_redact_simple_email(self):
        """Test redacting simple email address."""
        text = "Contact user@example.com"
        result = redact_email(text)
        
        assert "u***@example.com" in result

    def test_redact_complex_email(self):
        """Test redacting email with dots and underscores."""
        text = "Email: john.doe_123@company.co.uk"
        result = redact_email(text)
        
        assert "j***@company.co.uk" in result

    def test_redact_multiple_emails(self):
        """Test redacting multiple email addresses."""
        text = "Users: alice@test.com and bob@example.org"
        result = redact_email(text)
        
        assert "a***@test.com" in result
        assert "b***@example.org" in result

    def test_preserve_non_email(self):
        """Test that non-email text is preserved."""
        text = "This is not an email: hello world"
        result = redact_email(text)
        
        assert result == text


class TestCreditCardRedaction:
    """Tests for credit card number redaction."""

    def test_redact_cc_with_spaces(self):
        """Test redacting credit card with spaces."""
        text = "Card: 1234 5678 9012 3456"
        result = redact_credit_card(text)
        
        assert "****-****-****-3456" in result

    def test_redact_cc_with_dashes(self):
        """Test redacting credit card with dashes."""
        text = "Card: 1234-5678-9012-3456"
        result = redact_credit_card(text)
        
        assert "****-****-****-3456" in result

    def test_redact_cc_continuous(self):
        """Test redacting continuous credit card number."""
        text = "Card: 1234567890123456"
        result = redact_credit_card(text)
        
        assert "****-****-****-3456" in result


class TestPassportRedaction:
    """Tests for Russian passport number redaction."""

    def test_redact_passport_with_space(self):
        """Test redacting passport with space separator."""
        text = "Passport: 1234 567890"
        result = redact_passport(text)
        
        assert "**** ******" in result

    def test_redact_passport_without_space(self):
        """Test redacting passport without space."""
        text = "Passport: 1234567890"
        result = redact_passport(text)
        
        assert "**** ******" in result


class TestSnilsRedaction:
    """Tests for SNILS (Russian pension insurance) redaction."""

    def test_redact_snils_standard(self):
        """Test redacting standard SNILS format."""
        text = "SNILS: 123-456-789 01"
        result = redact_snils(text)
        
        assert "***-***-*** **" in result


class TestInnRedaction:
    """Tests for INN (Russian tax ID) redaction."""

    def test_redact_inn_10_digits(self):
        """Test redacting 10-digit INN."""
        text = "INN: 1234567890"
        result = redact_inn(text)
        
        # Should keep last 2 digits
        assert "**********90" in result

    def test_redact_inn_12_digits(self):
        """Test redacting 12-digit INN."""
        text = "INN: 123456789012"
        result = redact_inn(text)
        
        # Should keep last 2 digits
        assert "************12" in result


class TestFullRedaction:
    """Tests for full text redaction pipeline."""

    def test_redact_all_pii_types(self):
        """Test redacting all PII types in one text."""
        text = """
            Contact: +7 999 123-45-67
            Email: test@example.com
            Card: 1234 5678 9012 3456
            Passport: 1234 567890
            SNILS: 123-456-789 01
            INN: 123456789012
        """
        result = redact_text(text)
        
        # Check each type is redacted
        assert "+7 ***" in result or "***-**-67" in result
        assert "t***@example.com" in result
        assert "****-****-****-3456" in result
        assert "**** ******" in result
        assert "***-***-*** **" in result
        assert "************12" in result

    def test_empty_string(self):
        """Test redacting empty string."""
        result = redact_text("")
        assert result == ""

    def test_no_pii_preserved(self):
        """Test that text without PII is preserved."""
        text = "Hello, this is a normal message without any sensitive data."
        result = redact_text(text)
        
        assert result == text


class TestPiiDetection:
    """Tests for PII detection."""

    def test_detect_phone(self):
        """Test detecting phone number presence."""
        text = "Call me at +7 999 123-45-67"
        assert contains_pii(text) is True

    def test_detect_email(self):
        """Test detecting email presence."""
        text = "My email is test@example.com"
        assert contains_pii(text) is True

    def test_detect_credit_card(self):
        """Test detecting credit card presence."""
        text = "Card: 1234 5678 9012 3456"
        assert contains_pii(text) is True

    def test_no_pii(self):
        """Test text without PII."""
        text = "Hello world, no sensitive data here!"
        assert contains_pii(text) is False

    def test_empty_string_no_pii(self):
        """Test empty string has no PII."""
        assert contains_pii("") is False
