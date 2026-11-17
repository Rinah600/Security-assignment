# Checks HTTP security headers and evaluates their values

def check_security_headers(headers, url=""):

    print("\n========== SECURITY HEADERS SCAN ==========")

    results = []

    def add_result(header, status, value, message):
        results.append({
            "header": header,
            "status": status,
            "value": value,
            "message": message
        })

        print(f"\n[{status}] {header}")
        print(f"Value: {value}")
        print(f"Message: {message}")

    # 1. Strict-Transport-Security (HSTS)
    header = "Strict-Transport-Security"
    value = headers.get(header)

    if value is None:
        add_result(header, "WARN", "Missing",
                   "HSTS header is missing. It is recommended for HTTPS websites.")
    else:
        directives = [part.strip() for part in value.split(";")]
        max_age = None

        for directive in directives:
            if directive.lower().startswith("max-age="):
                try:
                    max_age = int(directive.split("=", 1)[1].strip().strip('"'))
                except ValueError:
                    pass

        if max_age is None or max_age < 0:
            add_result(header, "WARN", value,
                       "HSTS has an invalid or missing max-age.")
        elif max_age >= 31536000:
            add_result(header, "PASS", value,
                       "HSTS has a recommended max-age of at least one year.")
        else:
            add_result(header, "WARN", value,
                       "HSTS max-age is shorter than one year.")

    # 2. Content-Security-Policy (CSP)
    header = "Content-Security-Policy"
    value = headers.get(header)

    if value is None:
        add_result(header, "WARN", "Missing",
                   "CSP is missing. Consider defining a content security policy.")
    else:
        directives = {}

        for part in value.split(";"):
            tokens = part.strip().split()

            if tokens:
                directives[tokens[0].lower()] = tokens[1:]

        script_sources = directives.get(
            "script-src",
            directives.get("default-src", [])
        )

        if "unsafe-inline" in [
            source.strip("'").lower() for source in script_sources
        ]:
            add_result(header, "WARN", value,
                       "Script policy allows unsafe-inline.")
        elif "unsafe-eval" in [
            source.strip("'").lower() for source in script_sources
        ]:
            add_result(header, "WARN", value,
                       "Script policy allows unsafe-eval.")
        else:
            add_result(header, "INFO", value,
                       "CSP is present. Its full security requires further review.")

    # 3. X-Content-Type-Options
    header = "X-Content-Type-Options"
    value = headers.get(header)

    if value is None:
        add_result(header, "WARN", "Missing",
                   "X-Content-Type-Options is missing.")
    elif value.strip().lower() == "nosniff":
        add_result(header, "PASS", value,
                   "Correct value. MIME sniffing is disabled.")
    else:
        add_result(header, "WARN", value,
                   "Expected value: nosniff.")

    # 4. X-Frame-Options
    header = "X-Frame-Options"
    value = headers.get(header)

    if value is None:
        add_result(header, "WARN", "Missing",
                   "X-Frame-Options is missing. Check CSP frame-ancestors too.")
    elif value.strip().upper() in ["DENY", "SAMEORIGIN"]:
        add_result(header, "PASS", value,
                   "Recognised frame protection value.")
    else:
        add_result(header, "WARN", value,
                   "Unrecognised or unsupported X-Frame-Options value.")

    # 5. Referrer-Policy
    header = "Referrer-Policy"
    value = headers.get(header)

    recommended = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin"
    ]

    if value is None:
        add_result(header, "WARN", "Missing",
                   "Referrer-Policy is missing.")
    else:
        policies = [
            policy.strip().lower()
            for policy in value.split(",")
        ]

        effective_policy = policies[-1]

        if effective_policy in recommended:
            add_result(header, "PASS", value,
                       "Recognised privacy-conscious referrer policy.")
        else:
            add_result(header, "WARN", value,
                       "Review the referrer policy for possible information exposure.")

    # 6. Permissions-Policy
    header = "Permissions-Policy"
    value = headers.get(header)

    if value is None:
        add_result(header, "WARN", "Missing",
                   "Permissions-Policy is missing.")
    elif value.strip():
        add_result(header, "INFO", value,
                   "Permissions-Policy is present. Review individual feature rules.")
    else:
        add_result(header, "WARN", value,
                   "Permissions-Policy is empty.")

    # Scan summary
    print("\n========== SCAN SUMMARY ==========")

    passed = sum(result["status"] == "PASS" for result in results)
    warnings = sum(result["status"] == "WARN" for result in results)
    info = sum(result["status"] == "INFO" for result in results)

    print(f"Total headers checked: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Warnings: {warnings}")
    print(f"Informational: {info}")

    return results