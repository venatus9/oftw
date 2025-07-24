import requests
import csv
LM_STUDIO_API_URLimport requests

LM_STUDIO_API_URL = "http://localhost:1234/v1/chat/completions"

try:
  with open("proc_data.json", 'r') as f:
    content = f.read()
except:
  print("Failed to read or parse input file")

prompt = "You are analysing a json log file to identify the presence of malicious activity.\nReport any and all particularly suspicious actions in csv format. Do not report non-suspicious evidence\n\n" + content
payload = {
  "model": "YOUR_MODEL",
  "messages": [
    {"role": "user", "content": prompt}
  ],
  "temperature": 0.7,
  "max_tokens": 200
}
response = requests.post(LM_STUDIO_API_URL, json=payload)

if response.status_code == 200:
  data = response.json()
  reply = data['choices'][0]['message']['content']
  writer = csv.writer(open("/path/to/my/csv/file", 'w'))
else:
  print("Request failed with status code:", response.status_code)
  print(response.text)
