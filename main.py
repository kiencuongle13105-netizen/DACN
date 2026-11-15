"""DACN Week 4 upgraded entrypoint. Runs the two-stage durable autostart agent.

Use: py -3.12 main.py --config config/agent.json
"""
from agent.autostart import main

if __name__ == '__main__':
    main()
