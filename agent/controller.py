from tools.file_tool import read_file

from tools.knowledge_tool import (
    search_knowledge
)

from tools.memory_tool import (
    save_memory,
    get_memories
)

from tools.database_tool import (
    query_database
)

from logs.security_logger import (
    log_security_event
)

from security.agent_detector import (
    detect_agent_spoofing
)


class AgentController:

    def process_request(
        self,
        user_input
    ):

        suspicious_keywords = [

            "ignore previous instructions",

            "delete all",

            "bypass",

            "override"
        ]

        result = (
            detect_agent_spoofing(
                user_input
            )
        )

        if result:

            log_security_event(

                "Inter-Agent Spoofing Attempt",

                result["severity"]
            )

            return f"""
ATTACK DETECTED

Attack:
{result['attack']}

OWASP:
{result['owasp']}

Severity:
{result['severity']}

Recommendation:
{result['recommendation']}

Matched Patterns:
{', '.join(result['findings'])}
"""

        for keyword in suspicious_keywords:

            if keyword in user_input.lower():

                log_security_event(
                    f"Suspicious Prompt: {user_input}",
                    "MEDIUM"
                )

        if "read" in user_input.lower():

            parts = user_input.split()

            if len(parts) < 2:

                return (
                    "Please specify a filename"
                )

            filename = parts[1]

            return read_file(
                filename
            )

        elif "search" in user_input.lower():

            parts = user_input.split()

            if len(parts) < 2:

                return (
                    "Please specify a knowledge file"
                )

            filename = parts[1]

            return search_knowledge(
                filename
            )

        elif "show memory" in user_input.lower():

            return get_memories()

        elif "remember" in user_input.lower():

            memory_text = (
                user_input
                .strip()[8:]
                .strip()
            )

            return save_memory(
                memory_text
            )

        elif "employee" in user_input.lower():

            return query_database()

        return "Unknown Request"