"""Analysis pipeline orchestrator."""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from uuid import UUID

from domain.analysis import AnalysisContext, AnalysisResult
from domain.indicators import Indicator
from shared.logging import get_logger

logger = get_logger(__name__)


@runtime_checkable
class Analyzer(Protocol):
    """Protocol for analyzer components."""
    
    name: str
    
    async def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Indicator]:
        """
        Analyze the artifact and return indicators.
        
        Args:
            context: Analysis context with artifact and state
            
        Returns:
            List of indicators detected by this analyzer
        """
        ...


@dataclass
class AnalysisPolicy:
    """Policy controlling analysis behavior."""
    
    enable_active_analysis: bool = True
    passive_threshold_for_active: float = 0.30
    max_indicators: int = 50
    
    def allow_active_analysis(
        self,
        context: AnalysisContext,
        passive_risk_score: float,
    ) -> bool:
        """
        Determine if active analysis should be performed.
        
        Active analysis (opening URLs, executing code) is only allowed
        when passive analysis indicates sufficient risk to justify it.
        """
        if not self.enable_active_analysis:
            return False
        
        # Always allow active analysis for high-risk passive scores
        if passive_risk_score >= self.passive_threshold_for_active:
            return True
        
        # For low-risk scores, skip active analysis to save resources
        return False


@dataclass
class AnalysisPipeline:
    """
    Main analysis pipeline orchestrator.
    
    Executes analyzers in the correct order:
    1. Passive analyzers (no network calls)
    2. Decision point: is active analysis needed?
    3. Active analyzers (sandboxed network calls)
    4. Scoring and verdict
    """
    
    passive_analyzers: list[Analyzer] = field(default_factory=list)
    active_analyzers: list[Analyzer] = field(default_factory=list)
    scorer: object | None = None
    policy: AnalysisPolicy = field(default_factory=AnalysisPolicy)
    
    async def run(self, context: AnalysisContext) -> AnalysisResult:
        """
        Execute the full analysis pipeline.
        
        Args:
            context: Analysis context with artifact
            
        Returns:
            Analysis result with verdict and indicators
        """
        from datetime import datetime, timezone
        
        context.started_at = datetime.now(timezone.utc)
        all_indicators: list[Indicator] = []
        
        try:
            # Phase 1: Passive analysis (safe, no network)
            logger.info(
                "analysis_phase_started",
                analysis_id=context.analysis_id,
                phase="passive",
                analyzer_count=len(self.passive_analyzers),
            )
            
            for analyzer in self.passive_analyzers:
                try:
                    indicators = await analyzer.analyze(context)
                    context.passive_indicators.extend(indicators)
                    all_indicators.extend(indicators)
                    logger.debug(
                        "analyzer_completed",
                        analyzer_name=analyzer.name,
                        indicators_found=len(indicators),
                    )
                except Exception as e:
                    logger.error(
                        "passive_analyzer_error",
                        analyzer_name=analyzer.name,
                        error=str(e),
                    )
                    # Continue with other analyzers
            
            # Calculate intermediate score
            passive_score = 0.0
            if self.scorer:
                passive_score = self.scorer.calculate(context.passive_indicators)
            
            # Phase 2: Decision - proceed to active analysis?
            if self.policy.allow_active_analysis(context, passive_score):
                logger.info(
                    "analysis_phase_started",
                    analysis_id=context.analysis_id,
                    phase="active",
                    analyzer_count=len(self.active_analyzers),
                    passive_score=passive_score,
                )
                
                for analyzer in self.active_analyzers:
                    try:
                        indicators = await analyzer.analyze(context)
                        context.active_indicators.extend(indicators)
                        all_indicators.extend(indicators)
                        logger.debug(
                            "analyzer_completed",
                            analyzer_name=analyzer.name,
                            indicators_found=len(indicators),
                        )
                    except Exception as e:
                        logger.error(
                            "active_analyzer_error",
                            analyzer_name=analyzer.name,
                            error=str(e),
                        )
            else:
                logger.info(
                    "active_analysis_skipped",
                    analysis_id=context.analysis_id,
                    passive_score=passive_score,
                    reason="below_threshold",
                )
            
            # Phase 3: Calculate final score and verdict
            if self.scorer:
                context.risk_score = self.scorer.calculate(all_indicators)
            
            # Limit indicators to prevent overflow
            if len(all_indicators) > self.policy.max_indicators:
                all_indicators = sorted(
                    all_indicators,
                    key=lambda i: i.weighted_score(),
                    reverse=True,
                )[:self.policy.max_indicators]
            
            completed_at = datetime.now(timezone.utc)
            processing_time_ms = int((completed_at - context.started_at).total_seconds() * 1000)
            
            context.completed_at = completed_at
            
            return AnalysisResult(
                analysis_id=context.analysis_id,
                correlation_id=context.correlation_id,
                verdict=context.verdict or "ALLOW",
                risk_score=context.risk_score,
                indicators=all_indicators,
                evidence_ids=context.evidence_ids,
                processing_time_ms=processing_time_ms,
            )
            
        except Exception as e:
            logger.exception(
                "pipeline_execution_error",
                analysis_id=context.analysis_id,
                error=str(e),
            )
            
            completed_at = datetime.now(timezone.utc)
            processing_time_ms = int((completed_at - context.started_at).total_seconds() * 1000) if context.started_at else 0
            
            return AnalysisResult(
                analysis_id=context.analysis_id,
                correlation_id=context.correlation_id,
                verdict="PROCESSING_ERROR",
                risk_score=0.0,
                indicators=[],
                evidence_ids=[],
                processing_time_ms=processing_time_ms,
                error_message=str(e),
            )
