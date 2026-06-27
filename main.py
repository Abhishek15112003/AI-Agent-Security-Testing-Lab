from agent.controller import AgentController

agent = AgentController()

while True:

    user_input = input("\nEnter Request: ")

    if user_input.lower() == "exit":
        break

    result = agent.process_request(user_input)

    print(result)