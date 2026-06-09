"""
LLM Client Abstraction
Unified interface for multiple LLM providers.
"""

import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    model: str
    provider: str
    usage: Dict[str, int] = None
    error: str = ""
    
    def __post_init__(self):
        if self.usage is None:
            self.usage = {}


class LLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    def generate(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: User prompt
            system: Optional system prompt
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            
        Returns:
            LLMResponse object
        """
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get provider name."""
        pass
    
    @property
    @abstractmethod
    def model_name(self) -> str:
        """Get model name."""
        pass


class AnthropicClient(LLMClient):
    """Anthropic Claude API client."""
    
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        """
        Initialize Anthropic client.
        
        Args:
            api_key: Anthropic API key
            model: Model name (default: claude-sonnet-4-20250514)
        """
        self.api_key = api_key
        self.model = model
    
    @property
    def provider_name(self) -> str:
        return "anthropic"
    
    @property
    def model_name(self) -> str:
        return self.model
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> LLMResponse:
        """Generate response using Anthropic API."""
        try:
            import anthropic
        except ImportError:
            return LLMResponse(
                content="",
                model=self.model,
                provider="anthropic",
                error="anthropic library not installed. Install with: pip install anthropic"
            )
        
        if not self.api_key:
            return LLMResponse(
                content="",
                model=self.model,
                provider="anthropic",
                error="No API key configured"
            )
        
        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            
            message = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system or "You are a cybersecurity incident report writer.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            content = message.content[0].text if message.content else ""
            
            return LLMResponse(
                content=content,
                model=self.model,
                provider="anthropic",
                usage={
                    'input_tokens': message.usage.input_tokens,
                    'output_tokens': message.usage.output_tokens,
                }
            )
            
        except Exception as e:
            return LLMResponse(
                content="",
                model=self.model,
                provider="anthropic",
                error=str(e)
            )


class OpenAIClient(LLMClient):
    """OpenAI API client."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        """
        Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key
            model: Model name (default: gpt-4o)
        """
        self.api_key = api_key
        self.model = model
    
    @property
    def provider_name(self) -> str:
        return "openai"
    
    @property
    def model_name(self) -> str:
        return self.model
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> LLMResponse:
        """Generate response using OpenAI API."""
        try:
            import openai
        except ImportError:
            return LLMResponse(
                content="",
                model=self.model,
                provider="openai",
                error="openai library not installed. Install with: pip install openai"
            )
        
        if not self.api_key:
            return LLMResponse(
                content="",
                model=self.model,
                provider="openai",
                error="No API key configured"
            )
        
        try:
            client = openai.OpenAI(api_key=self.api_key)
            
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            
            content = response.choices[0].message.content if response.choices else ""
            
            return LLMResponse(
                content=content,
                model=self.model,
                provider="openai",
                usage={
                    'input_tokens': response.usage.prompt_tokens,
                    'output_tokens': response.usage.completion_tokens,
                }
            )
            
        except Exception as e:
            return LLMResponse(
                content="",
                model=self.model,
                provider="openai",
                error=str(e)
            )


class OllamaClient(LLMClient):
    """Ollama local LLM client."""
    
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3"):
        """
        Initialize Ollama client.
        
        Args:
            host: Ollama server URL
            model: Model name (default: llama3)
        """
        self.host = host.rstrip('/')
        self.model = model
    
    @property
    def provider_name(self) -> str:
        return "ollama"
    
    @property
    def model_name(self) -> str:
        return self.model
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> LLMResponse:
        """Generate response using Ollama API."""
        try:
            import requests
        except ImportError:
            return LLMResponse(
                content="",
                model=self.model,
                provider="ollama",
                error="requests library not installed"
            )
        
        try:
            full_prompt = prompt
            if system:
                full_prompt = f"{system}\n\n{prompt}"
            
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    }
                },
                timeout=300
            )
            
            if response.status_code != 200:
                return LLMResponse(
                    content="",
                    model=self.model,
                    provider="ollama",
                    error=f"Ollama API error: {response.status_code}"
                )
            
            data = response.json()
            content = data.get('response', '')
            
            return LLMResponse(
                content=content,
                model=self.model,
                provider="ollama",
                usage={
                    'input_tokens': data.get('prompt_eval_count', 0),
                    'output_tokens': data.get('eval_count', 0),
                }
            )
            
        except requests.RequestException as e:
            return LLMResponse(
                content="",
                model=self.model,
                provider="ollama",
                error=f"Connection error: {e}. Is Ollama running?"
            )
        except Exception as e:
            return LLMResponse(
                content="",
                model=self.model,
                provider="ollama",
                error=str(e)
            )


def get_llm_client(
    provider: str = None,
    api_key: str = None,
    model: str = None,
    host: str = None
) -> LLMClient:
    """
    Get an LLM client based on provider.
    
    Args:
        provider: Provider name (anthropic, openai, ollama)
        api_key: API key (for cloud providers)
        model: Model name
        host: Host URL (for Ollama)
        
    Returns:
        LLMClient instance
    """
    from ..config import config
    
    # Default to Anthropic
    if provider is None:
        provider = config.get('report_llm_provider', 'anthropic')
    
    provider = provider.lower()
    
    if provider == 'anthropic':
        if api_key is None:
            api_key = config.anthropic_api_key
        if model is None:
            model = config.get('report_llm_model', 'claude-sonnet-4-20250514')
        return AnthropicClient(api_key=api_key, model=model)
    
    elif provider == 'openai':
        if api_key is None:
            api_key = config.openai_api_key
        if model is None:
            model = config.get('report_llm_model', 'gpt-4o')
        return OpenAIClient(api_key=api_key, model=model)
    
    elif provider == 'ollama':
        if host is None:
            host = config.get('ollama_host', 'http://localhost:11434')
        if model is None:
            model = config.get('ollama_model', 'llama3')
        return OllamaClient(host=host, model=model)
    
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


