# Group Exercise: Cloud and Kubernetes Security Scenarios

This exercise helps you reason about cloud and container security concepts without requiring prior Kubernetes expertise.

You will work in groups, choose **one scenario**, and prepare a short discussion and present-back.

This is not a technical test.
The goal is to practise identifying **responsibility boundaries, realistic risks, and high‑impact security controls**.

---

## Instructions

1. Form groups of 4–5 people.
2. Review the scenarios below.
3. As a group, **choose one scenario** to work on.
4. Complete the discussion prompts for your chosen scenario.
5. Prepare a **2–3 minute summary** to present back.

---

## Scenario A: Containerised Application on a Managed Cloud Platform

### Context

- A web application is packaged as a container.
- It is built in a CI/CD pipeline and deployed to a managed cloud service.
- The application exposes a public API endpoint.
- It uses cloud storage and a managed database.
- The cloud provider operates the underlying platform.

### Discussion Prompts

- Which parts of this setup are secured by the cloud provider?
- What security responsibilities remain with the application team?
- Where could misconfiguration expose data or increase risk?
- Which single control would most reduce risk here?

---

## Scenario B: CI/CD Pipeline Building and Deploying Containers

### Context

- Developers commit code to a shared repository.
- A CI/CD pipeline builds Docker images and pushes them to a registry.
- The pipeline uses credentials to access cloud services.
- Images are deployed automatically after successful builds.

### Discussion Prompts

- What are the main supply‑chain risks in this scenario?
- Where could secrets or credentials be exposed?
- How could a vulnerable or malicious image reach production?
- Which control would most effectively reduce this risk?

---

## Scenario C: Shared Kubernetes Cluster for Multiple Teams

### Context

- A managed Kubernetes cluster is shared by multiple application teams.
- Each team deploys workloads into its own namespace.
- Service accounts are used by applications.
- Networking works by default unless restricted.

### Discussion Prompts

- What does the cloud provider secure versus the customer?
- How could overly broad permissions increase blast radius?
- Where do namespaces help, and where are they insufficient?
- Which single improvement would most increase safety?

---

## Scenario D: Unexpected Runtime Behaviour

### Context

- A running container suddenly starts making outbound network connections.
- No recent application deployment has occurred.
- Credentials used appear valid and authorised.
- Logs show normal API access patterns.

### Discussion Prompts

- What could explain this behaviour?
- What visibility or logging would help investigate?
- Which responsibilities fall on the provider, and which on the customer?
- What runtime control would have detected or limited this sooner?

---

## Group Output

Be ready to present:

1. The scenario your group chose
2. One misunderstood or weak responsibility boundary
3. One realistic failure or misconfiguration
4. One improvement you would prioritise

---

## Final Reminder

Most cloud and container security failures are not caused by missing tools,
but by misunderstood responsibilities and overly trusting defaults.

Assume misconfiguration is inevitable.
Design controls to limit impact and speed up detection.