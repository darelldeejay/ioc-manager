from flask import Flask, render_template
import datetime

app = Flask(__name__)
app.secret_key = 'dev'

@app.route('/')
def test_render():
    return render_template("index.html",
        current_flashes_list=[],
        server_messages_list=[],
        ips=["1.1.1.1|2023-01-01|0"],
        total_ips=1,
        contador_manual=1,
        contador_csv=0,
        contador_api=0,
        contador_tags={"Multicliente":0,"BPE":0,"Test":1},
        union_total=1,
        union_by_source={"manual":1},
        union_by_tag={"Test":1},
        union_by_source_tag={"manual":{"Test":1}},
        request_actions=[],
        messages=[],
        history_items=[],
        ip_tags={"1.1.1.1": ["Test"]},
        ip_alerts={},
        known_tags=["Test"],
        error=None,
        current_feed="main",
        user_role="admin",
        maintenance_mode=False,
        # Helper mocks if needed
        session={}
    )

if __name__ == "__main__":
    # Mock helpers
    @app.context_processor
    def inject_helpers():
        return {
            "tag_color": lambda x: "#000000",
            "days_remaining": lambda x, y: 0
        }
        
    with app.test_request_context():
        try:
            print(test_render())
            print("Render Success")
        except Exception as e:
            import traceback
            traceback.print_exc()
