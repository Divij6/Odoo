
from flask import Flask, render_template, jsonify, request, Response
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import datetime
import gridfs
import threading
import cv2
import time
import numpy as np
import joblib
from ultralytics import YOLO
import json
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import my_twilio_config

try:
    import EncryptionConfig
    from cryptography.fernet import Fernet

    cipher = Fernet(EncryptionConfig.ENCRYPTION_KEY)
except Exception:
    cipher = None
    print("⚠️ Warning: EncryptionConfig not found or invalid. Data will not be decrypted.")


MONGO_CONNECTION_STRING = ""
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
NEUTRALIZED_DIR = os.path.join(BASE_DIR, "neutralized_clips")
output_dir = "detection_clips"
CALL_TIMEOUT_SECONDS = 20

app = Flask(__name__, static_folder="static")


detection_active = False
detection_thread = None
current_frame = None
frame_lock = threading.Lock()
SHUTDOWN_REQUESTED = threading.Event()
ALERT_ACKNOWLEDGED_EVENT = threading.Event()


client = MongoClient(MONGO_CONNECTION_STRING)
db = client["security_events"]
collection = db["threat_logs"]
fs = gridfs.GridFS(db)


try:
    weapon_model = YOLO("runs/detect/train3/weights/best.pt")
    panic_model = joblib.load("panic_detector_svm(4).pkl")
    print("✅ AI models loaded successfully.")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    weapon_model = None
    panic_model = None

CATEGORIES = ["Normal", "Anomaly"]


try:
    twilio_client = Client(my_twilio_config.TWILIO_ACCOUNT_SID, my_twilio_config.TWILIO_AUTH_TOKEN)
    with open("contacts.json", "r") as f:
        contacts = json.load(f)
    sorted_contacts = sorted(contacts, key=lambda c: c['priority'])
    print(f"✅ Twilio client and contacts loaded. {len(sorted_contacts)} contacts sorted by priority.")
except Exception as e:
    print(f"❌ Error setting up Twilio/Contacts: {e}")
    twilio_client = None
    sorted_contacts = []



def decrypt_if_possible(val):
    if val is None:
        return None
    try:
        if cipher and isinstance(val, (bytes, bytearray)):
            return cipher.decrypt(bytes(val)).decode()
    except Exception:
        return str(val)
    return val


def encrypt_if_possible(s):
    if cipher and isinstance(s, str):
        return cipher.encrypt(s.encode())
    return s


def encrypt_data(data_string):
    if not cipher or not isinstance(data_string, str):
        return data_string
    encoded_text = data_string.encode('utf-8')
    encrypted_text = cipher.encrypt(encoded_text)
    return encrypted_text


def update_frame_for_stream(frame):
    global current_frame
    with frame_lock:
        # Encode frame as JPEG for streaming
        ret, buffer = cv2.imencode('.jpg', frame)
        if ret:
            current_frame = buffer.tobytes()


# === AI Detection Functions ===
def extract_features_from_frames(frames):
    hog = cv2.HOGDescriptor()
    hog_feats = []
    for gray in frames:
        resized = cv2.resize(gray, (64, 128))
        feats = hog.compute(resized).flatten()
        hog_feats.append(feats)
    if not hog_feats:
        return np.zeros(3780)
    return np.mean(hog_feats, axis=0)


def log_initial_threat(description):
    try:
        document = {
            "description": encrypt_data(description),
            "camera": 1,
            "location": "VIT Pune",
            "officer": encrypt_data("Unassigned"),
            "status": encrypt_data("Open"),
            "timestamp": datetime.datetime.now()
        }
        result = collection.insert_one(document)
        print(f"📝 Encrypted event logged to database. ID: {result.inserted_id}")
        return result.inserted_id
    except Exception as e:
        print(f"❌ Error logging initial event to database: {e}")
        return None


def store_snapshot(frame, current_clip_basename, db_id):
    if not (fs and db_id and frame is not None):
        print("⚠️ Skipping snapshot: fs/db_id/frame not available.")
        return
    try:
        os.makedirs(output_dir, exist_ok=True)
        snapshot_path = os.path.join(output_dir, f"{current_clip_basename}.jpg")
        success = cv2.imwrite(snapshot_path, frame)
        if not success:
            print("❌ cv2.imwrite failed to save snapshot.")
            return

        with open(snapshot_path, "rb") as img_file:
            file_id = fs.put(img_file, filename=f"{current_clip_basename}.jpg", threat_id=db_id)

        print(f"🖼️ Snapshot stored in MongoDB GridFS. File ID: {file_id}")
        collection.update_one(
            {"_id": db_id},
            {"$set": {
                "gridfs_snapshot_id": file_id,
                "snapshot_path": snapshot_path
            }}
        )
    except Exception as e:
        print(f"❌ Failed to store snapshot in MongoDB: {e}")


def trigger_alert_and_update_db(db_id, description):
    if not twilio_client or not sorted_contacts:
        print("Twilio not configured or no contacts. Skipping alerts.")
        return

    gmaplink = "https://maps.app.goo.gl/Gbqcr8eUUhHYmZZS6"
    alert_message = f"⚠️ ALERT: {description} detected at VIT Pune. Please respond immediately. Google Maps Link to reach there in fastest way possible: {gmaplink}"
    officer_assigned = False

    for contact in sorted_contacts:
        if SHUTDOWN_REQUESTED.is_set():
            print("Shutdown requested during alert escalation. Halting alerts.")
            return

        print(f"\n--- Escalating to Priority {contact['priority']}: {contact['name']} ---")
        try:
            print(f"Sending WhatsApp alert to {contact['name']}...")
            twilio_client.messages.create(
                from_=my_twilio_config.TWILIO_WHATSAPP_NUMBER,
                body=alert_message,
                to=f"whatsapp:{contact['phone']}"
            )
            print("  -> WhatsApp sent successfully.")
        except TwilioRestException as e:
            print(f"  -> Failed to send WhatsApp: {e}")

        try:
            print(f"Initiating voice call to {contact['name']}...")
            call = twilio_client.calls.create(
                to=contact['phone'],
                from_=my_twilio_config.TWILIO_VOICE_NUMBER,
                url=my_twilio_config.TWIML_BIN_URL
            )
            print(f"  -> Voice call initiated. SID: {call.sid}. Waiting for response...")

            start_time = time.time()
            while time.time() - start_time < CALL_TIMEOUT_SECONDS:
                if SHUTDOWN_REQUESTED.is_set():
                    return
                time.sleep(3)
                call_status = twilio_client.calls(call.sid).fetch().status
                print(f"    (Current call status: {call_status})")

                if call_status in ['in-progress', 'completed']:
                    print(f"✅ Call ANSWERED by {contact['name']}!")
                    officer_assigned = True
                    break

                if call_status in ['failed', 'busy', 'no-answer', 'canceled']:
                    print(f"❌ Call not answered by {contact['name']}. Status: {call_status}.")
                    break

            if officer_assigned:
                collection.update_one(
                    {"_id": db_id},
                    {"$set": {
                        "officer": encrypt_data(contact['name']),
                        "status": encrypt_data("Live + Allocated")
                    }}
                )
                print("  -> Database record updated with responding officer.")
                print("\n✅ Alert Acknowledged. Signaling main loop to exit after clip finishes...")
                ALERT_ACKNOWLEDGED_EVENT.set()
                return

        except TwilioRestException as e:
            print(f"  -> Failed to initiate call: {e}. Escalating...")
            continue

    if not officer_assigned:
        print("\n--- Escalation Complete: No one answered the call. ---")
        collection.update_one(
            {"_id": db_id},
            {"$set": {"status": encrypt_data("Open - Unacknowledged")}}
        )
        print("  -> Database record updated to 'Unacknowledged'.")


def finalize_clip(out, current_clip_basename):
    if out:
        out.release()
    os.makedirs(output_dir, exist_ok=True)
    video_filepath = os.path.join(output_dir, f"{current_clip_basename}.mp4")
    print(f"🎥 Video saved locally at: {video_filepath}")


def ai_detection_loop(chunk_size=30, clip_duration=10, camera_index=0):
    global detection_active, current_frame
    os.makedirs(output_dir, exist_ok=True)


    cap = None
    for i in range(3):
        try:
            cap = cv2.VideoCapture(i, cv2.CAP_DSHOW)  # DirectShow for Windows
            if cap.isOpened():
                print(f"Successfully opened camera index {i} with DirectShow")
                break
            cap.release()

            cap = cv2.VideoCapture(i)  # Default backend
            if cap.isOpened():
                print(f"Successfully opened camera index {i} with default backend")
                break
            cap.release()
        except:
            continue

    if not cap or not cap.isOpened():
        print(f"❌ Cannot open any camera")
        detection_active = False
        return

    fps, width, height = 30, int(cap.get(3)), int(cap.get(4))
    recording, out, last_detected_time, frame_count, buffer = False, None, 0, 0, []
    current_clip_basename, triggering_description = None, ""
    display_description = "Normal"
    active_threads = []
    db_id = None

    try:
        while detection_active and not SHUTDOWN_REQUESTED.is_set():
            ret, frame = cap.read()
            if not ret:
                continue


            update_frame_for_stream(frame)

            frame_count += 1
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            buffer.append(gray)


            weapon_detected = False
            if weapon_model:
                weapon_results = weapon_model(frame, conf=0.80, device=0, verbose=False)
                weapon_detected = any(len(r.boxes) > 0 for r in weapon_results)

                for r in weapon_results:
                    for box in r.boxes:
                        x1, y1, x2, y2 = map(int, box.xyxy[0])
                        conf_box, cls = float(box.conf[0]), int(box.cls[0])
                        label = weapon_model.names[cls]
                        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                        cv2.putText(frame, f"{label} {conf_box:.2f}", (x1, y1 - 10),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)


            panic_detected = False
            if panic_model and frame_count % chunk_size == 0 and buffer:
                features = extract_features_from_frames(buffer).reshape(1, -1)
                pred_label = CATEGORIES[panic_model.predict(features)[0]]
                confidence = panic_model.predict_proba(features)[0].max()
                buffer = []
                if pred_label == "Anomaly" and confidence > 0.85:
                    panic_detected = True


            current_threat_description = "Normal"
            if weapon_detected and panic_detected:
                current_threat_description = "HIGH THREAT: Weapon and Crowd Panic Detected!"
            elif weapon_detected:
                current_threat_description = "WARNING: Weapon detected, crowd calm or no crowd around"
            elif panic_detected:
                current_threat_description = "WARNING: Crowd panic detected"

            # Add text overlay to frame
            if current_threat_description != "Normal":
                display_description = current_threat_description
            cv2.putText(frame, display_description, (20, height - 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)

            # Update frame for streaming after overlays
            update_frame_for_stream(frame)

            # --- Recording and alerting ---
            if (weapon_detected or panic_detected) and not recording:
                print(f"⚠️ Threat detected → {current_threat_description}")
                recording = True
                last_detected_time = time.time()
                triggering_description = current_threat_description
                db_id = log_initial_threat(triggering_description)

                current_clip_basename = f"clip_{int(last_detected_time)}"
                video_filepath = os.path.join(output_dir, f"{current_clip_basename}.mp4")
                fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                out = cv2.VideoWriter(video_filepath, fourcc, fps, (width, height))

                if db_id:
                    store_snapshot(frame, current_clip_basename, db_id)
                    collection.update_one({"_id": db_id}, {"$set": {"clip_name": f"{current_clip_basename}.mp4"}})

                    alert_thread = threading.Thread(
                        target=trigger_alert_and_update_db,
                        args=(db_id, triggering_description)
                    )
                    alert_thread.start()
                    active_threads.append(alert_thread)


            if recording and out:
                out.write(frame)
                if time.time() - last_detected_time >= clip_duration:
                    recording = False
                    finalize_clip(out, current_clip_basename)
                    out = None

            time.sleep(0.03)  # ~30 FPS

    except Exception as e:
        print(f"❌ Error in AI detection loop: {e}")
    finally:
        print("Exiting AI detection loop...")
        cap.release()
        if out:
            finalize_clip(out, current_clip_basename)
        for t in active_threads:
            t.join()
        detection_active = False

        with frame_lock:
            current_frame = None
        print("✅ AI detection stopped safely.")



@app.route("/")
def index():
    return render_template("live_feed.html")


@app.route("/live_threats")
def live_threats_page():
    return render_template("live_threats.html")


@app.route("/neutralized")
def neutralized_page():
    return render_template("neutralized.html")


@app.route("/police_stations")
def police_page():
    return render_template("police_stations.html")



@app.route('/video_feed')
def video_feed():
    def generate_frames():
        global current_frame
        while True:
            with frame_lock:
                if current_frame is not None:
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + current_frame + b'\r\n')
                else:

                    blank_frame = np.zeros((480, 640, 3), dtype=np.uint8)
                    cv2.putText(blank_frame, "Camera Not Active", (150, 240),
                                cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                    ret, buffer = cv2.imencode('.jpg', blank_frame)
                    if ret:
                        yield (b'--frame\r\n'
                               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.033)  # ~30 FPS

    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')



@app.route("/api/start_detection", methods=["POST"])
def start_detection():
    global detection_active, detection_thread

    if detection_active:
        return jsonify({"error": "Detection already running"}), 400

    if not weapon_model or not panic_model:
        return jsonify({"error": "AI models not loaded"}), 500

    detection_active = True
    SHUTDOWN_REQUESTED.clear()
    ALERT_ACKNOWLEDGED_EVENT.clear()

    detection_thread = threading.Thread(target=ai_detection_loop, args=(30, 10, 0))
    detection_thread.start()

    return jsonify({"message": "AI detection started", "status": "active"})


@app.route("/api/stop_detection", methods=["POST"])
def stop_detection():
    global detection_active, detection_thread

    if not detection_active:
        return jsonify({"error": "Detection not running"}), 400

    detection_active = False
    SHUTDOWN_REQUESTED.set()

    if detection_thread and detection_thread.is_alive():
        detection_thread.join(timeout=5)

    return jsonify({"message": "AI detection stopped", "status": "inactive"})


@app.route("/api/detection_status")
def detection_status():
    return jsonify({
        "active": detection_active,
        "models_loaded": (weapon_model is not None) and (panic_model is not None)
    })



@app.route("/api/threats")
def api_threats():
    docs = collection.find().sort("timestamp", -1).limit(200)
    out = []
    for d in docs:
        status = decrypt_if_possible(d.get("status"))
        if status and "Neutral" in str(status):
            continue

        out.append({
            "id": str(d["_id"]),
            "description": decrypt_if_possible(d.get("description")) or "N/A",
            "status": status,
            "officer": decrypt_if_possible(d.get("officer")),
            "location": d.get("location"),
            "camera": d.get("camera"),
            "clip_gridfs_id": str(d.get("clip_gridfs_id")) if d.get("clip_gridfs_id") else None,
            "gridfs_snapshot_id": str(d.get("gridfs_snapshot_id")) if d.get("gridfs_snapshot_id") else None,
            "snapshot_path": d.get("snapshot_path"),
            "clip_name": d.get("clip_name"),
            "timestamp": d.get("timestamp").isoformat() if d.get("timestamp") else None
        })
    return jsonify(out)


@app.route("/api/neutralized")
def api_neutralized_list():
    docs = collection.find().sort("timestamp", -1).limit(500)
    out = []
    for d in docs:
        status = decrypt_if_possible(d.get("status"))
        if status and "Neutral" in str(status):
            out.append({
                "id": str(d["_id"]),
                "description": decrypt_if_possible(d.get("description")) or "N/A",
                "status": status,
                "officer": decrypt_if_possible(d.get("officer")),
                "location": d.get("location"),
                "camera": d.get("camera"),
                "clip_gridfs_id": str(d.get("clip_gridfs_id")) if d.get("clip_gridfs_id") else None,
                "gridfs_snapshot_id": str(d.get("gridfs_snapshot_id")) if d.get("gridfs_snapshot_id") else None,
                "snapshot_path": d.get("snapshot_path"),
                "clip_name": d.get("clip_name"),
                "timestamp": d.get("timestamp").isoformat() if d.get("timestamp") else None
            })
    return jsonify(out)


@app.route("/api/neutralize/<id>", methods=["POST"])
def api_neutralize(id):
    try:
        doc = collection.find_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "invalid id"}), 400
    if not doc:
        return jsonify({"error": "not found"}), 404


    gridfs_id = doc.get("clip_gridfs_id")
    if gridfs_id and fs.exists(ObjectId(gridfs_id)):
        fs.delete(ObjectId(gridfs_id))
        print(f"Deleted clip from GridFS with ID: {gridfs_id}")


    snap_id = doc.get("gridfs_snapshot_id")
    if snap_id and fs.exists(ObjectId(snap_id)):
        fs.delete(ObjectId(snap_id))
        print(f"Deleted snapshot from GridFS with ID: {snap_id}")

    collection.update_one({"_id": ObjectId(id)},
                          {"$set": {"status": encrypt_if_possible("Neutralized"),
                                    "neutralized_at": datetime.datetime.now()}})
    return jsonify({"ok": True})



@app.route("/gridfs/<file_id>")
def get_file(file_id):
    try:
        file_obj = fs.get(ObjectId(file_id))
        return Response(file_obj.read(), mimetype="video/mp4")
    except Exception as e:
        return jsonify({"error": f"File not found: {e}"}), 404


@app.route("/gridfs_image/<file_id>")
def get_image(file_id):
    try:
        file_obj = fs.get(ObjectId(file_id))
        return Response(file_obj.read(), mimetype="image/jpeg")
    except Exception as e:
        return jsonify({"error": f"Image not found: {e}"}), 404


if __name__ == "__main__":
    os.makedirs(NEUTRALIZED_DIR, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)