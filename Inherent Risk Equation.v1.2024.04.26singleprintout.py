import os
import datetime

def get_weight(value):
    """Prompt for and return the numerical weight for a low, medium, or high value, along with the input."""
    while True:
        user_input = input(f"Enter {value} (L/M/H): ").lower()
        if user_input in ['l', 'm', 'h']:
            response_text = f"{value} (L/M/H): {user_input}"
            if "Effort" in value:
                weight_mapping = {'l': 1, 'm': 2/3, 'h': 1/3}
            else:
                weight_mapping = {'l': 1/3, 'm': 2/3, 'h': 1}
            return weight_mapping[user_input], response_text
        else:
            print("Invalid input. Please enter L, M, or H.")

def get_binary_input(variable_name):
    """Prompt for and return binary input (Y/N) as numerical 1 or 0, along with the input."""
    while True:
        response = input(f"Is {variable_name} (Y/N)? ").lower()
        if response in ['y', 'n']:
            response_text = f"Is {variable_name} (Y/N)? {response}"
            return 1 if response == 'y' else 0, response_text
        else:
            print("Invalid input. Please enter Y or N.")

def calculate_dsv(data_sensitivity, binary_responses):
    """Calculate the Data Severity Rating."""
    d_value = data_sensitivity
    op_value = sum(binary_responses) / len(binary_responses)
    return op_value * d_value

def calculate_threat_score(ds, weight_i, weight_a):
    """Calculate the Threat Score."""
    c = ds * (1/3)
    i = weight_i * (1/3)
    a = weight_a * (1/3)
    return c + i + a

def process_entry(scanner, entry_name):
    """Process a single entry and capture user responses."""
    print(f"\nProcessing entry: {entry_name} with scanner: {scanner}")
    responses = []

    data_sensitivity, response = get_weight("Confidentiality level of the Data")
    responses.append(response)

    binary_responses = []
    binary_variables = ['Copy data?', 'Read data?', 'Update data?', 'Configure data?', 'Execute operations?']
    for var in binary_variables:
        binary_response, response = get_binary_input(f"The vulnerability able to {var}")
        binary_responses.append(binary_response)
        responses.append(response)

    dsv = calculate_dsv(data_sensitivity, binary_responses)

    impact, response = get_weight("Impact Score")
    responses.append(response)
    access, response = get_weight("Availability Score")
    responses.append(response)

    threat_score = calculate_threat_score(data_sensitivity, impact, access)

    epss_prompt = input("Is there an EPSS value (Y/N)? ").lower()
    responses.append(f"Is there an EPSS value (Y/N)? {epss_prompt}")
    if epss_prompt == 'y':
        epss_value = float(input("Enter EPSS value (0 to 1): "))
        responses.append(f"Enter EPSS value (0 to 1): {epss_value}")
        loeq = epss_value
    else:
        vm_input, response = get_weight("Exploit Maturity")
        responses.append(response)
        loe_input, response = get_weight("Level of Effort")
        responses.append(response)
        loeq = (vm_input + loe_input) / 2

    ir_value = threat_score * loeq

    # Determine the priority level based on IR value
    if ir_value < 0.25:
        priority = "P4"
    elif ir_value < 0.5:
        priority = "P3"
    elif ir_value < 0.75:
        priority = "P2"
    else:
        priority = "P1"

    results = (
        f"\nData Severity Rating (DSV): {dsv}"
        f"\nThreat Score (T): {threat_score}"
        f"\nLevel of Effort Quotient (LOEQ): {loeq}"
        f"\nIR Value (Threat Score × LOEQ): {ir_value}"
        f"\n\nPriority Level: {priority}"
    )
    full_response = "\n".join(responses) + "\n" + results
    print(full_response)

    # Save the results to a file
    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    filename = f"{scanner}_{priority}_{timestamp}_{entry_name}.txt"
    file_path = os.path.join(os.getcwd(), filename)
    with open(file_path, 'w') as file:
        file.write(f"Entry Name: {entry_name}\n\n" + full_response)
    print(f"Results saved to {filename}")

    return full_response

def main():
    scanners = ["SonarCloud", "Qualys", "AWS Inspector", "Carbon Black", "Snyk", "BugBounty", "DAST", "Trivy"]

    while True:
        print("Available scanners:")
        for idx, scanner in enumerate(scanners):
            print(f"{idx+1}. {scanner}")

        scanner_choice = int(input("Select a scanner by number: ")) - 1
        scanner = scanners[scanner_choice]

        entry_name = input("Please give the entry a name: ")
        process_entry(scanner, entry_name)

        another_entry = input("Do you have another entry? (Y/N): ").lower()
        if another_entry != 'y':
            break

if __name__ == "__main__":
    main()
