"""Basic LLM usage examples for ThreatWeaver.

This script demonstrates basic usage of the LLM abstraction layer.
Make sure to set OPENROUTER_API_KEY in your .env file before running.

Run with:
    python examples/llm_basic_usage.py
"""

import asyncio

from src.llm import Message, MessageRole, create_llm_provider


def example_basic_completion():
    """Basic synchronous completion example."""
    print("=" * 60)
    print("Example 1: Basic Completion")
    print("=" * 60)

    provider = create_llm_provider()

    messages = [
        Message(role=MessageRole.SYSTEM, content="You are a cybersecurity expert."),
        Message(
            role=MessageRole.USER,
            content="Explain what a SQL injection attack is in 2 sentences.",
        ),
    ]

    response = provider.complete(messages)

    print(f"\nResponse: {response.content}")
    print(f"\nTokens used: {response.usage.total_tokens}")
    print(f"Model: {response.model}")
    print()


async def example_async_completion():
    """Async completion example."""
    print("=" * 60)
    print("Example 2: Async Completion")
    print("=" * 60)

    provider = create_llm_provider()

    messages = [
        Message(
            role=MessageRole.USER,
            content="What are the top 3 most common web application vulnerabilities?",
        ),
    ]

    response = await provider.complete_async(messages)

    print(f"\nResponse: {response.content}")
    print(f"\nTokens used: {response.usage.total_tokens}")
    print()


def example_streaming():
    """Streaming completion example."""
    print("=" * 60)
    print("Example 3: Streaming Response")
    print("=" * 60)

    provider = create_llm_provider()

    messages = [
        Message(
            role=MessageRole.USER,
            content="List 5 best practices for secure password management.",
        ),
    ]

    print("\nStreaming response:")
    for chunk in provider.stream(messages):
        print(chunk, end="", flush=True)

    print("\n")


async def example_async_streaming():
    """Async streaming example."""
    print("=" * 60)
    print("Example 4: Async Streaming")
    print("=" * 60)

    provider = create_llm_provider()

    messages = [
        Message(
            role=MessageRole.USER,
            content="Explain how HTTPS works in simple terms.",
        ),
    ]

    print("\nStreaming response:")
    async for chunk in provider.stream_async(messages):
        print(chunk, end="", flush=True)

    print("\n")

    # Clean up
    await provider.cleanup()


def example_different_models():
    """Example using different models."""
    print("=" * 60)
    print("Example 5: Different Models")
    print("=" * 60)

    # Fast and cheap model
    provider_fast = create_llm_provider(
        model="anthropic/claude-3-haiku",
        temperature=0.5,
    )

    messages = [Message(role=MessageRole.USER, content="What is phishing?")]

    response = provider_fast.complete(messages)
    print(f"\nClaude Haiku response: {response.content}")
    print(f"Tokens: {response.usage.total_tokens}")

    # More capable model
    provider_capable = create_llm_provider(
        model="anthropic/claude-3.5-sonnet",
        temperature=0.7,
    )

    response = provider_capable.complete(messages)
    print(f"\nClaude Sonnet response: {response.content}")
    print(f"Tokens: {response.usage.total_tokens}")
    print()


def example_with_conversation():
    """Example with multi-turn conversation."""
    print("=" * 60)
    print("Example 6: Multi-turn Conversation")
    print("=" * 60)

    provider = create_llm_provider()

    # Start conversation
    messages = [
        Message(role=MessageRole.SYSTEM, content="You are a helpful security advisor."),
        Message(role=MessageRole.USER, content="What is XSS?"),
    ]

    response = provider.complete(messages)
    print(f"\nUser: What is XSS?")
    print(f"Assistant: {response.content}")

    # Continue conversation
    messages.append(Message(role=MessageRole.ASSISTANT, content=response.content))
    messages.append(Message(role=MessageRole.USER, content="How can I prevent it?"))

    response = provider.complete(messages)
    print(f"\nUser: How can I prevent it?")
    print(f"Assistant: {response.content}")
    print()


async def main():
    """Run all examples."""
    print("\n🤖 ThreatWeaver LLM Abstraction Layer Examples\n")

    # Sync examples
    example_basic_completion()
    example_streaming()
    example_different_models()
    example_with_conversation()

    # Async examples
    await example_async_completion()
    await example_async_streaming()

    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
