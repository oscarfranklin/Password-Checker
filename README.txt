Password Policy Checker - README
Overview

The Password Policy Checker is a GUI-based Python application designed to evaluate the strength of a password and ensure it complies with security guidelines such as NIST and OWASP standards. Additionally, the tool tracks password expiration, prevents password reuse, and provides visual feedback on password strength.

This application is built using PyQt5 for the graphical interface and pyfiglet for generating ASCII banners in the terminal.
Features

    NIST and OWASP Compliance: Checks passwords against NIST and OWASP guidelines for complexity and length.
    Password Strength Evaluation: Provides a password strength score based on length and complexity, visualized with color-coded feedback.
    Password Expiration Check: Ensures that passwords are changed after a specified expiration period.
    Password Reuse Prevention: Prevents the use of recent passwords (with configurable history length).
    Graphical User Interface (GUI): Simple GUI built with PyQt5 to allow users to input passwords and view results.

Requirements

Make sure you have the following dependencies installed:

bash

pip install PyQt5 pyfiglet

Libraries Used

    PyQt5: For creating the GUI interface.
    pyfiglet: For generating ASCII art banners in the terminal.
    time: For tracking the timestamp of password changes.
    collections: Specifically, deque is used to store the last X passwords.
    re: For regular expressions to evaluate password complexity.

Usage
Running the Application

You can start the password checker by running the script in your terminal or IDE:

bash

python password_checker.py

Graphical User Interface (GUI)

When you run the application, a window will appear with the following elements:

    Password Input Field: A field where you can enter the password to be checked.
    Check Button: After entering a password, click this button to check the password against the policy.
    Result Label: Displays whether the password satisfies NIST and/or OWASP guidelines, or if it is too weak.
    Password Strength: Shows a visual indicator of the password's strength, from weak to strong (red to green).

Password Strength Scoring

Password strength is calculated based on length and complexity (uppercase, lowercase, digits, special characters):

    Length: Adds strength based on the number of characters.
    Complexity: Checks for a mix of character types (uppercase, lowercase, numbers, special characters).

Password Expiration and History

    Expiration: The tool enforces password expiration after 90 days (configurable in the code).
    History: Tracks the last 3 passwords used (configurable) and prevents reuse.

ASCII Banner

An ASCII banner is displayed in the terminal using pyfiglet, showing the name of the application.
Password Guidelines
NIST Guidelines

    Minimum 8 characters.
    Must include:
        At least one uppercase letter.
        At least one lowercase letter.
        At least one digit.
        At least one special character (@$!%*?&).

OWASP Guidelines

    Minimum 12 characters.
    Must include:
        At least one uppercase letter.
        At least one lowercase letter.
        At least one digit.
        At least one non-alphanumeric character.

Customization
Password Expiration and History Settings

In the code, you can adjust the following constants:

    PASSWORD_EXPIRATION_DAYS: Number of days before a password expires.
    PASSWORD_HISTORY_LIMIT: Number of recent passwords stored to prevent reuse.

Visualizing Password Strength

The password strength is visualized using color-coded feedback:

    Red: Weak (Strength 0-1).
    Orange: Fair (Strength 2-3).
    Yellow: Good (Strength 4-5).
    Green: Strong (Strength 6+).

Example

    Enter a password in the input field.
    Click the "Check Password" button.
    View results in the GUI:
        NIST/OWASP compliance.
        Password strength score with color-coded feedback.
        If applicable, see messages about password expiration or reuse.

License

This project is open-source and can be freely used and modified.