import pandas as pd
from faker import Faker
import random

fake = Faker("en_AU") #Australian locale for realistic data

def generate_row(row_id):
    return {
        "customer_id": row_id,
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "credit_card": fake.credit_card_number(),
        "signup_date": fake.date_this_decade(),
        "product": fake.word(),
    }

def generate_dataset(num_rows=200):
    rows = []
    for i in range(1, num_rows + 1):
        rows.append(generate_row(i))
    return pd.DataFrame(rows)

if __name__ == "__main__":
    df = generate_dataset(200)
    df.to_csv("data/sample_customers.csv", index=False)
    print(f"Generated {len(df)} rows -> data/sample_customers.csv")