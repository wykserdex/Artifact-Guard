"""Form analysis for phishing detection."""

import re
from html.parser import HTMLParser
from typing import Optional

from domain.indicators import Indicator


class FormHTMLParser(HTMLParser):
    """Parse HTML to extract form information."""
    
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form: Optional[dict] = None
        self.in_form = False
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == "form":
            self.in_form = True
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
                "has_password_field": False,
                "has_credit_card_field": False,
            }
        
        elif tag == "input" and self.in_form and self.current_form:
            input_type = attrs_dict.get("type", "text").lower()
            input_name = attrs_dict.get("name", "").lower()
            
            if input_type == "password":
                self.current_form["has_password_field"] = True
            
            # Check for credit card fields
            if any(keyword in input_name for keyword in ["card", "credit", "ccv", "cvv", "expiry"]):
                self.current_form["has_credit_card_field"] = True
            
            self.current_form["inputs"].append({
                "type": input_type,
                "name": input_name,
                "required": "required" in attrs_dict,
            })
        
        elif tag == "button" and self.in_form and self.current_form:
            button_type = attrs_dict.get("type", "submit").lower()
            if button_type == "submit":
                self.current_form["inputs"].append({
                    "type": "submit",
                    "name": attrs_dict.get("name", ""),
                    "required": False,
                })
    
    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
            self.in_form = False


class FormAnalyzer:
    """Analyze forms for phishing indicators."""
    
    name = "form_analyzer"
    
    SUSPICIOUS_ACTIONS = [
        "login.php", "signin", "authenticate", "verify",
        "update-account", "confirm-identity", "secure-login"
    ]
    
    def analyze(self, html: str, base_url: str) -> list[Indicator]:
        """Analyze HTML for suspicious forms."""
        indicators = []
        
        parser = FormHTMLParser()
        try:
            parser.feed(html)
        except Exception:
            return indicators
        
        for form in parser.forms:
            # Check for password fields
            if form["has_password_field"]:
                score = 0.3
                
                # Check for suspicious action
                action_lower = form["action"].lower()
                if any(suspicious in action_lower for suspicious in self.SUSPICIOUS_ACTIONS):
                    score += 0.4
                    indicators.append(Indicator(
                        name="suspicious_login_form",
                        score=score,
                        severity="high" if score > 0.6 else "medium",
                        explanation=f"Login form with suspicious action: {form['action'][:50]}",
                        evidence_ids=[],
                    ))
                else:
                    indicators.append(Indicator(
                        name="credential_form",
                        score=0.35,
                        severity="medium",
                        explanation="Page contains a form requesting credentials",
                        evidence_ids=[],
                    ))
            
            # Check for credit card fields
            if form["has_credit_card_field"]:
                indicators.append(Indicator(
                    name="financial_data_form",
                    score=0.5,
                    severity="high",
                    explanation="Page contains a form requesting financial data",
                    evidence_ids=[],
                ))
            
            # Check for excessive required fields
            required_count = sum(1 for inp in form["inputs"] if inp.get("required"))
            if required_count > 5:
                indicators.append(Indicator(
                    name="excessive_required_fields",
                    score=0.3,
                    severity="low",
                    explanation=f"Form has {required_count} required fields (potential data harvesting)",
                    evidence_ids=[],
                ))
        
        return indicators
