from __future__ import unicode_literals
import json
import logging
from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
session_store = {}


@app.route("/", methods=["POST"])
def main():
    req_json = request.json
    logging.info("Request: %r", req_json)
    res_json = {
        "version": req_json["version"],
        "session": req_json["session"],
        "response": {"end_session": False},
    }
    process_dialog(req_json, res_json)
    logging.info("Response: %r", res_json)
    return json.dumps(res_json, ensure_ascii=False, indent=2)


def process_dialog(req, res):
    uid = req["session"]["user_id"]
    # Инициализируем сессию: round 1 - покупка слона, round 2 - покупка кролика.
    if req["session"]["new"]:
        session_store[uid] = {
            "options": ["Не хочу.", "Не буду.", "Отстань!"],
            "round": 1
        }
        res["response"]["text"] = "Привет! Купи слона!"
        res["response"]["buttons"] = generate_buttons(uid)
        return

    utterance = req["request"]["original_utterance"].lower()
    key_phrases = ["ладно", "куплю", "покупаю", "хорошо"]
    current_round = session_store[uid].get("round", 1)

    if any(phrase in utterance for phrase in key_phrases):
        if current_round == 1:
            res["response"]["text"] = "Поздравляем, вы купили слона! А теперь купите кролика!"
            session_store[uid]["round"] = 2
            session_store[uid]["options"] = ["Не хочу.", "Не буду.", "Отстань!"]
            res["response"]["buttons"] = generate_buttons(uid)
        else:
            res["response"]["text"] = "Поздравляем, вы купили кролика!"
        return

    if current_round == 1:
        res["response"]["text"] = 'Все говорят "%s", а ты купи слона!' % req["request"]["original_utterance"]
    else:
        res["response"]["text"] = 'Все говорят "%s", а ты купи кролика!' % req["request"]["original_utterance"]
    res["response"]["buttons"] = generate_buttons(uid)


def generate_buttons(user_id):
    session = session_store[user_id]
    buttons = [{"title": opt, "hide": True} for opt in session["options"][:2]]
    session["options"] = session["options"][1:]
    session_store[user_id] = session
    if len(buttons) < 2:
        buttons.append({
            "title": "Ладно",
            "url": "https://market.yandex.ru/search?text=слон" if session.get("round", 1) == 1 \
                else "https://market.yandex.ru/search?text=кролик",
            "hide": True
        })
    return buttons


if __name__ == "__main__":
    app.run()
