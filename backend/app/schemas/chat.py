"""Schemas for RAG chatbot API."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ConversationMessage(BaseModel):
    """A message in the conversation history."""
    role: str = Field(..., description="Role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    """Request schema for chat endpoint."""
    
    query: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="The user's question about phishing"
    )
    analysis_context: Optional[Dict[str, Any]] = Field(
        None,
        description="Current email analysis context for the AI to reference"
    )
    conversation_history: Optional[List[ConversationMessage]] = Field(
        None,
        max_length=10,
        description="Previous messages in the conversation for context (max 10)"
    )


class ChatSource(BaseModel):
    """A source from the knowledge base used in the response."""
    
    title: str = Field(..., description="Title of the knowledge source")
    id: str = Field(..., description="Unique identifier of the source")


class ChatResponse(BaseModel):
    """Response schema for chat endpoint."""
    
    answer: str = Field(..., description="The AI-generated answer")
    sources: List[ChatSource] = Field(
        default_factory=list,
        description="Knowledge base sources used"
    )
    model_used: str = Field(..., description="The model used to generate the response")
    query: str = Field(..., description="The original query")


class SuggestedQuestionsResponse(BaseModel):
    """Response schema for suggested questions endpoint."""
    
    questions: List[str] = Field(
        ...,
        description="List of suggested questions users can ask"
    )


class AnalysisRecommendationRequest(BaseModel):
    """Request schema for AI recommendation based on analysis."""
    
    attack_score: Optional[int] = Field(None, description="Sublime attack score (0-100)")
    verdict: Optional[str] = Field(None, description="Verdict: safe, suspicious, malicious")
    rule_count: Optional[int] = Field(None, description="Number of detection rules matched")
    insight_count: Optional[int] = Field(None, description="Number of insights triggered")
    vt_malicious: Optional[int] = Field(None, description="VirusTotal malicious count")
    vt_suspicious: Optional[int] = Field(None, description="VirusTotal suspicious count")
    sender_domain: Optional[str] = Field(None, description="Email sender domain")
    subject: Optional[str] = Field(None, description="Email subject")
    has_attachments: Optional[bool] = Field(None, description="Whether email has attachments")
    attachment_types: Optional[List[str]] = Field(None, description="List of attachment file extensions")


class AnalysisRecommendationResponse(BaseModel):
    """Response schema for AI recommendation."""
    
    recommendation: str = Field(..., description="Short AI recommendation based on analysis")
    risk_level: str = Field(..., description="Risk level: low, medium, high, critical")
    actions: List[str] = Field(default_factory=list, description="Recommended actions to take")
