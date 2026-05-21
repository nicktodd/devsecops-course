# Lab: Secure Coding – Identifying and Fixing Vulnerabilities

## Purpose

This lab helps you recognise common secure coding mistakes across different languages and environments.

You will:

- identify vulnerabilities in short examples
- understand the root cause, not just the symptom
- suggest practical mitigations using secure coding principles

This exercise is language-agnostic. Focus on patterns, not syntax.

---

## Scenario Overview

You are reviewing a set of application components developed by different teams.

Each component functions correctly, but may contain security weaknesses.

Your task is to:

1. Identify the vulnerability  
2. Explain the root cause  
3. Categorise the issue type  
4. Suggest a secure fix  

---

## Exercise 1

### Code Example

    @app.route('/user')
    def get_user():
        user_id = request.args.get("id")
        query = "SELECT * FROM users WHERE id = " + user_id
        return db.execute(query)

### Questions

- What is the vulnerability?
- Why does this happen?
- How would you fix it?
- Is this a design, coding, or configuration issue?

---

## Exercise 2

### Code Example

    <div>
      Welcome, {{ username }}
    </div>

The value of `username` comes directly from user input.

### Questions

- What is the risk here?
- Why is input validation alone not sufficient?
- What should be done to make this safe?
- Is this a design, coding, or configuration issue?

---

## Exercise 3

### Code Example

    ObjectInputStream in = new ObjectInputStream(request.getInputStream());
    User user = (User) in.readObject();

### Questions

- Why is this dangerous?
- What kind of attack could occur?
- What safer alternatives exist?
- Is this a design, coding, or configuration issue?

---

## Exercise 4

### Code Example

    char buffer[10];
    strcpy(buffer, user_input);

### Questions

- What type of vulnerability is present?
- What is the root cause?
- Why are these bugs dangerous even when they do not immediately crash?
- Is this a design, coding, or configuration issue?

---

## Exercise 5

### Example

Here is a requirements.txt file

    flask
    requests
    internal-utils

### Questions

- What risks exist in this configuration?
- What attack patterns could exploit this?
- How should dependencies be managed more securely?
- Is this a design, coding, or configuration issue?

---

## Exercise 6

### Code Example

    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()

### Questions

- What is wrong with this approach?
- Why is this algorithm unsuitable?
- What should be used instead?
- Is this a design, coding, or configuration issue?

---

## Exercise 7

### Code Example

    filename = request.args.get("file")
    open("/data/" + filename)

### Questions

- What kind of risk could this introduce?
- Why is this dangerous?
- What validation or controls should be added?
- Is this a design, coding, or configuration issue?

---

## Exercise 8

Assume you can only fix three issues immediately.

Choose:

- Issue 1:
- Issue 2:
- Issue 3:

Explain your reasoning based on:

- exploitability  
- impact  
- likelihood  
- blast radius  

---

## Exercise 9

For each example, identify which control is missing:

- Input validation  
- Output encoding  
- Safe memory handling  
- Secure dependency management  
- Strong cryptography  
- Trust boundary enforcement  

---

## Reflection

### Pattern Recognition

Which patterns appeared most frequently?

- Trusting user input  
- Missing validation  
- Unsafe defaults  
- Over-trusting libraries  
- Security added too late  

---

### Key Insight

What surprised you most about these vulnerabilities?

---

### Real-World Application

Think about your own systems:

- Where could similar issues exist?
- Which category concerns you most?

---

## Key Takeaways

- Secure coding is about recognising patterns, not memorising rules  
- Many vulnerabilities come from:
  - trust assumptions  
  - unsafe defaults  
  - poor handling of input and external data  
- Prevention during development is significantly cheaper than fixing issues later  
- Strong defaults, validation, and controlled dependencies reduce risk significantly  