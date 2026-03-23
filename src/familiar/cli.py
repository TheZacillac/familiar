"""Simple CLI entry point for the Familiar agent."""

import sys

from .agent import build_agent


def main():
    agent = build_agent()

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        _run_once(agent, query)
    else:
        _repl(agent)


def _run_once(agent, query: str):
    """Run a single query and print the response."""
    for chunk in agent.stream(
        {"messages": [{"role": "user", "content": query}]},
        stream_mode="values",
    ):
        msg = chunk["messages"][-1]
        if msg.type == "ai" and msg.content:
            print(msg.content)


def _repl(agent):
    """Interactive chat loop."""
    print("Familiar — domain intelligence agent (type 'quit' to exit)")
    print()

    while True:
        try:
            query = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not query or query.lower() in ("quit", "exit"):
            break

        for chunk in agent.stream(
            {"messages": [{"role": "user", "content": query}]},
            stream_mode="values",
        ):
            msg = chunk["messages"][-1]
            if msg.type == "ai" and msg.content:
                print(f"\nfamiliar> {msg.content}\n")
