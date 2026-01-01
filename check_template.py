from flask import Flask
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader('templates'))
try:
    env.parse(env.loader.get_source(env, 'index.html')[0])
    print("Jinja2 Syntax OK")
except Exception as e:
    print(f"Jinja2 Error: {e}")
