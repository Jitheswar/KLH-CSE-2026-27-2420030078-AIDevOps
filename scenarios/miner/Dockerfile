FROM python:3.12-alpine

# Simulated compromise Scenario, for exercising detection only.
# No mining software, no pool address, no proof-of-work. See ../README.md.
WORKDIR /scenario
COPY scenario.py .

CMD ["python3", "scenario.py"]
