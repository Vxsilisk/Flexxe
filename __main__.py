import json
from .Flexxe import analyze

url = str(input('URL: ')).strip()
result = analyze(url)
print(json.dumps(result, indent=4))
