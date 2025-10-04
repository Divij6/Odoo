import cv2
import time
import numpy as np
import joblib
from ultralytics import YOLO
import os
from pymongo import MongoClient
from datetime import datetime
import json
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import my_twilio_config
import threading
from cryptography.fernet import Fernet
import EncryptionConfig
from gridfs import GridFS


output_dir = "detection_clips"
MONGO_CONNECTION_STRING = "mongodb+srv://gujarathibond:Divij&9475@atlas.i0mvluo.mongodb.net/?retryWrites=true&w=majority&appName=FrontEnd"
CALL_TIMEOUT_SECONDS = 20
THREAT_COOLDOWN_SECONDS = 40


SHUTDOWN_REQUESTED = threading.Event()
ALERT_ACKNOWLEDGED_EVENT = threading.Event()


try:
    client = MongoClient(MONGO_CONNECTION_STRING)
    db = client["security_events"]
    collection = db["threat_logs"]
    print("✅ Successfully connected to MongoDB.")
except Exception as e:
    print(f"❌ Could not connect to MongoDB: {e}")
    client = None

if client:
    fs = GridFS(db)
else:
    fs = None


try:
    cipher_suite = Fernet(EncryptionConfig.ENCRYPTION_KEY)
    print("✅ Encryption module loaded successfully.")
except Exception as e:
    print(f"❌ Error loading encryption key: {e}")
    cipher_suite = None


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


try:
    weapon_model = YOLO("runs/detect/train3/weights/best.pt")
    panic_model = joblib.load("panic_detector_svm(4).pkl")
    print("✅ AI models loaded successfully.")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    exit()

CATEGORIES = ["Normal", "Anomaly"]



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



def encrypt_data(data_string):
    if not cipher_suite or not isinstance(data_string, str):
        return data_string
    encoded_text = data_string.encode('utf-8')
    encrypted_text = cipher_suite.encrypt(encoded_text)
    return encrypted_text



def log_initial_threat(description):
    if not client:
        print("DB connection not available. Skipping DB log.")
        return None
    try:
        document = {
            "description": encrypt_data(description),
            "camera": 1,
            "location": "VIT Pune",
            "officer": encrypt_data("Unassigned"),
            "status": encrypt_data("Open"),
            "timestamp": datetime.now()
        }
        result = collection.insert_one(document)
        print(f"📝 Encrypted event logged to database. ID: {result.inserted_id}")
        return result.inserted_id
    except Exception as e:
        print(f"❌ Error logging initial event to database: {e}")
        return None


def store_snapshot(frame, current_clip_basename, db_id):
    """Take a snapshot and upload to MongoDB"""
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
            twilio_client.messages.create(from_=my_twilio_config.TWILIO_WHATSAPP_NUMBER, body=alert_message,
                                          to=f"whatsapp:{contact['phone']}")
            print("  -> WhatsApp sent successfully.")
        except TwilioRestException as e:
            print(f"  -> Failed to send WhatsApp: {e}")

        try:
            print(f"Initiating voice call to {contact['name']}...")
            call = twilio_client.calls.create(to=contact['phone'], from_=my_twilio_config.TWILIO_VOICE_NUMBER,
                                              url=my_twilio_config.TWIML_BIN_URL)
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


def finalize_clip(out, current_clip_basename, db_id):
    """Finalize video and upload it to GridFS."""
    if out:
        out.release()

    video_filepath = os.path.join(output_dir, f"{current_clip_basename}.mp4")
    print(f"🎥 Video saved locally at: {video_filepath}")

    # Give OpenCV time to finalize the file before uploading
    time.sleep(1)

    if fs and db_id and os.path.exists(video_filepath):
        try:
            with open(video_filepath, "rb") as f:
                file_id = fs.put(f, filename=f"{current_clip_basename}.mp4", threat_id=db_id)
            print(f"✅ Video stored in MongoDB GridFS. File ID: {file_id}")
            collection.update_one({"_id": db_id}, {"$set": {"gridfs_file_id": file_id}})
        except Exception as e:
            print(f"❌ Failed to store video in MongoDB: {e}")


def run_live_camera(chunk_size=30, clip_duration=10, camera_index=0):
    os.makedirs(output_dir, exist_ok=True)
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print(f"❌ Cannot open camera index {camera_index}")
        return

    fps, width, height = 30, int(cap.get(3)), int(cap.get(4))

    recording, out, last_detected_time = False, None, 0
    frame_count, buffer = 0, []
    current_clip_basename, triggering_description = None, ""
    display_description = "Normal"
    active_threads = []
    db_id = None
    confidence = 0.0

    # NEW: State variable for threat cooldown
    last_threat_trigger_time = 0

    try:
        while not SHUTDOWN_REQUESTED.is_set():
            ret, frame = cap.read()
            if not ret:
                print("⚠️ Can't receive frame (stream end?). Exiting ...")
                time.sleep(1)  # Wait a bit before trying again or exiting
                continue

            frame_count += 1
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            buffer.append(gray)

            # --- Weapon detection ---
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

            # --- Panic detection ---
            panic_detected = False
            if frame_count % chunk_size == 0 and buffer:
                features = extract_features_from_frames(buffer).reshape(1, -1)
                pred_label = CATEGORIES[panic_model.predict(features)[0]]
                confidence = panic_model.predict_proba(features)[0].max()
                buffer = []
                if pred_label == "Anomaly" and confidence > 0.85:
                    panic_detected = True

            # --- Display text ---
            current_threat_description = "Normal"
            if weapon_detected and panic_detected:
                current_threat_description = "HIGH THREAT: Weapon and Crowd Panic Detected!"
            elif weapon_detected:
                current_threat_description = "WARNING: Weapon detected"
            elif panic_detected:
                current_threat_description = "WARNING: Crowd panic detected"

            if current_threat_description != "Normal":
                display_description = current_threat_description
            cv2.putText(frame, display_description, (20, height - 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (50, 255, 255), 2)

            # --- Recording and alerting with COOLDOWN ---
            is_threat_active = weapon_detected or panic_detected
            is_cooldown_over = (time.time() - last_threat_trigger_time) > THREAT_COOLDOWN_SECONDS

            if is_threat_active and not recording and is_cooldown_over:
                print(f"⚠️ New threat sequence triggered → {current_threat_description}")

                # NEW: Reset the cooldown timer
                last_threat_trigger_time = time.time()

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
            elif is_threat_active and not is_cooldown_over:
                # NEW: Informative message when threat is detected but ignored
                remaining_cooldown = int(THREAT_COOLDOWN_SECONDS - (time.time() - last_threat_trigger_time))
                print(f"\r-> Threat detected, but in cooldown period. {remaining_cooldown}s remaining.", end="")

            # --- Write frames & Finalize Clip ---
            if recording:
                out.write(frame)
                if time.time() - last_detected_time >= clip_duration:
                    print(f"\n✅ Clip duration reached for {current_clip_basename}. Finalizing and uploading...")
                    recording = False
                    finalize_clip(out, current_clip_basename, db_id)
                    out = None
                    db_id = None  # Reset db_id after clip is done

                    if ALERT_ACKNOWLEDGED_EVENT.is_set():
                        print("✅ Alert was acknowledged and clip is saved. Shutting down now.")
                        SHUTDOWN_REQUESTED.set()
                        break

            cv2.imshow("Live Detection", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                SHUTDOWN_REQUESTED.set()
                break

    finally:
        print("\nExiting live camera feed...")
        cap.release()
        if out:
            finalize_clip(out, current_clip_basename, db_id)
        cv2.destroyAllWindows()
        for t in active_threads:
            t.join()
        print("✅ Live detection stopped safely.")


if __name__ == "__main__":
    try:
        run_live_camera(chunk_size=30, clip_duration=10)
    finally:
        if client:
            client.close()
        print("✅ MongoDB connection closed. Program exit.")