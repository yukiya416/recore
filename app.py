import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import json
import hashlib
from dotenv import load_dotenv
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import logging
import traceback
import base64
import re

####################################
# 1. 環境変数の読み込み
####################################

load_dotenv()
creds_json = os.getenv("GOOGLE_SHEETS_CREDENTIALS")
sheet_id = os.getenv("GOOGLE_SHEET_ID")
if not creds_json:
    print("Warning: Google Sheets API認証情報が設定されていません。")
if not sheet_id:
    print("Warning: Google Sheets IDが設定されていません。")

####################################
# 2. ロギング設定
####################################

class StackTraceFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "stacktrace"):
            record.stacktrace = ""
            if record.exc_info:
                record.stacktrace = "".join(traceback.format_exception(*record.exc_info))
        return True

logging.basicConfig(
    filename="error_log.txt",
    level=logging.ERROR,
    format="[%(asctime)s] [%(levelname)s] %(message)s\nStack Trace: %(stacktrace)s",
)
logger = logging.getLogger()
logger.addFilter(StackTraceFilter())

def log_error(message, error):
    logger.error(f"{message}: {str(error)}", exc_info=True)

####################################
# 3. Streamlitアプリ設定
####################################

st.set_page_config(
    page_title="リコア - 体重管理システム",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# カスタムCSS
st.markdown("""
<style>
  body { font-family: 'Roboto', sans-serif; }
  .title-text { text-align: center; font-size: 2rem; font-weight: bold; color: #2c3e50; margin-bottom: 1rem; }
  .subtitle-text { text-align: center; font-size: 1.2rem; color: #7f8c8d; margin-bottom: 2rem; }
  .footer { text-align: center; margin-top: 2rem; padding: 1rem 0; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 0.8rem; }
  .info-card { background: none; box-shadow: none; border: none; padding: 0; }
  .success-message { color: green; font-weight: bold; margin-bottom: 1rem; }
  .error-message { color: red; font-weight: bold; margin-bottom: 1rem; }
</style>
""", unsafe_allow_html=True)

####################################
# 4. Google Sheets API 設定
####################################

def setup_google_sheets():
    try:
        creds_json = os.getenv("GOOGLE_SHEETS_CREDENTIALS")
        if not creds_json:
            st.error("Google Sheets API認証情報が設定されていません。")
            return None
        creds_dict = json.loads(base64.b64decode(creds_json).decode('utf-8'))
        scope = [
            "https://spreadsheets.google.com/feeds",
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
        client = gspread.authorize(creds)
        sheet_id = os.getenv("GOOGLE_SHEET_ID")
        if not sheet_id:
            st.error("Google Sheets IDが設定されていません。")
            return None
        return client.open_by_key(sheet_id)
    except Exception as e:
        log_error("Google Sheets APIの設定中にエラーが発生しました", e)
        st.error("Google Sheets APIの設定中にエラーが発生しました。詳細はログを確認してください。")
        return None

####################################
# 5. セッション状態の初期化
####################################

def init_session_state():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user_id" not in st.session_state:
        st.session_state.user_id = ""
    if "user_name" not in st.session_state:
        st.session_state.user_name = ""
    if "user_birth" not in st.session_state:
        st.session_state.user_birth = ""
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = False
    if "view_user_id" not in st.session_state:
        st.session_state.view_user_id = ""
    if "message" not in st.session_state:
        st.session_state.message = ""
    if "message_type" not in st.session_state:
        st.session_state.message_type = ""
    if "users_data" not in st.session_state:
        st.session_state.users_data = pd.DataFrame()
    if "weight_data" not in st.session_state:
        st.session_state.weight_data = pd.DataFrame()
    if "page" not in st.session_state:
        st.session_state.page = "login"

init_session_state()

####################################
# 6. データ関連の関数
####################################

def load_users_data(sheet):
    try:
        worksheet = sheet.worksheet("users")
        users_data = pd.DataFrame(worksheet.get_all_records())
        if users_data.empty:
            users_data = pd.DataFrame(columns=["user_id", "name", "birth_date", "password", "height", "register_date", "is_admin"])
        return users_data
    except Exception as e:
        log_error("ユーザーデータの読み込み中にエラーが発生しました", e)
        return pd.DataFrame(columns=["user_id", "name", "birth_date", "password", "height", "register_date", "is_admin"])

def load_weight_data(sheet):
    try:
        worksheet = sheet.worksheet("weight_data")
        weight_data = pd.DataFrame(worksheet.get_all_records())
        if weight_data.empty:
            weight_data = pd.DataFrame(columns=["user_id", "date", "weight", "body_fat"])
        else:
            # データ型を変換
            weight_data["date"] = pd.to_datetime(weight_data["date"])
            weight_data["weight"] = pd.to_numeric(weight_data["weight"], errors="coerce")
            weight_data["body_fat"] = pd.to_numeric(weight_data["body_fat"], errors="coerce")
            # 体脂肪量/除脂肪体重を計算して列を追加
            weight_data["fat_mass"] = weight_data["weight"] * (weight_data["body_fat"] / 100)
            weight_data["lean_mass"] = weight_data["weight"] - weight_data["fat_mass"]
        return weight_data
    except Exception as e:
        log_error("体重データの読み込み中にエラーが発生しました", e)
        return pd.DataFrame(columns=["user_id", "date", "weight", "body_fat"])

def add_user(sheet, user_data):
    try:
        worksheet = sheet.worksheet("users")
        hashed_password = hashlib.sha256(user_data["password"].encode()).hexdigest()
        register_date = datetime.now().strftime("%Y-%m-%d")
        new_user = [
            user_data["user_id"],
            user_data["name"],
            user_data["birth_date"],
            hashed_password,
            str(user_data["height"]),
            register_date,
            "FALSE"
        ]
        worksheet.append_row(new_user)
        return True
    except Exception as e:
        log_error("ユーザー追加中にエラーが発生しました", e)
        return False

def update_user(sheet, user_id, update_data):
    try:
        worksheet = sheet.worksheet("users")
        users_data = pd.DataFrame(worksheet.get_all_records())
        user_idx = users_data[users_data["user_id"] == user_id].index
        if len(user_idx) == 0:
            return False
        # パスワードのみハッシュ化する
        for field, value in update_data.items():
            if field == "password" and value:
                hashed_password = hashlib.sha256(value.encode()).hexdigest()
                users_data.loc[user_idx, field] = hashed_password
            else:
                users_data.loc[user_idx, field] = value
        worksheet.clear()
        worksheet.update([users_data.columns.tolist()] + users_data.values.tolist())
        return True
    except Exception as e:
        log_error("ユーザー情報更新中にエラーが発生しました", e)
        return False

def delete_user(sheet, user_id):
    try:
        # usersシートから該当ユーザーを削除
        user_worksheet = sheet.worksheet("users")
        users_data = pd.DataFrame(user_worksheet.get_all_records())
        users_data = users_data[users_data["user_id"] != user_id]
        user_worksheet.clear()
        if not users_data.empty:
            user_worksheet.update([users_data.columns.tolist()] + users_data.values.tolist())
        else:
            user_worksheet.update([["user_id", "name", "birth_date", "password", "height", "register_date", "is_admin"]])

        # weight_dataシートから該当ユーザーのデータを削除
        weight_worksheet = sheet.worksheet("weight_data")
        weight_data = pd.DataFrame(weight_worksheet.get_all_records())
        weight_data = weight_data[weight_data["user_id"] != user_id]
        weight_worksheet.clear()
        if not weight_data.empty:
            weight_worksheet.update([weight_data.columns.tolist()] + weight_data.values.tolist())
        else:
            weight_worksheet.update([["user_id", "date", "weight", "body_fat"]])
        return True
    except Exception as e:
        log_error("ユーザー削除中にエラーが発生しました", e)
        return False

def add_weight_data(sheet, weight_data):
    try:
        worksheet = sheet.worksheet("weight_data")
        new_data = [
            weight_data["user_id"],
            weight_data["date"],
            weight_data["weight"],
            weight_data["body_fat"]
        ]
        worksheet.append_row(new_data)
        return True
    except Exception as e:
        log_error("体重データ追加中にエラーが発生しました", e)
        return False

def get_first_weight(weight_data, user_id):
    user_data = weight_data[weight_data["user_id"] == user_id]
    if user_data.empty:
        return None
    user_data = user_data.sort_values("date")
    return user_data.iloc[0]

def calculate_rankings_period(weight_data, users_data, period_selection):
    rankings = {"weight_loss": [], "weight_loss_rate": [], "lean_mass_increase": []}
    today = datetime.now()
    if period_selection == "すべて":
        cutoff = None
    elif period_selection == "過去1週間":
        cutoff = today - timedelta(days=7)
    elif period_selection == "過去1ヶ月":
        cutoff = today - timedelta(days=30)
    elif period_selection == "過去3ヶ月":
        cutoff = today - timedelta(days=90)
    elif period_selection == "過去6ヶ月":
        cutoff = today - timedelta(days=180)
    elif period_selection == "過去1年":
        cutoff = today - timedelta(days=365)

    for uid in users_data["user_id"].unique():
        user_w = weight_data[weight_data["user_id"] == uid]
        if cutoff is not None:
            user_w = user_w[user_w["date"] >= cutoff]
        if len(user_w) < 2:
            continue
        baseline = user_w.sort_values("date").iloc[0]
        latest = user_w.sort_values("date", ascending=False).iloc[0]
        weight_diff = baseline["weight"] - latest["weight"]
        loss_rate = (weight_diff / baseline["weight"] * 100) if baseline["weight"] > 0 else 0
        lean_diff = latest["lean_mass"] - baseline["lean_mass"]
        if weight_diff > 0:
            rankings["weight_loss"].append({"user_id": uid, "value": weight_diff})
            rankings["weight_loss_rate"].append({"user_id": uid, "value": loss_rate})
        if lean_diff > 0:
            rankings["lean_mass_increase"].append({"user_id": uid, "value": lean_diff})

    rankings["weight_loss"] = sorted(rankings["weight_loss"], key=lambda x: x["value"], reverse=True)
    rankings["weight_loss_rate"] = sorted(rankings["weight_loss_rate"], key=lambda x: x["value"], reverse=True)
    rankings["lean_mass_increase"] = sorted(rankings["lean_mass_increase"], key=lambda x: x["value"], reverse=True)
    return rankings

def get_user_by_id(users_data, user_id):
    user = users_data[users_data["user_id"] == user_id]
    if user.empty:
        return None
    return user.iloc[0]

def authenticate_user(users_data, user_id, password):
    user = get_user_by_id(users_data, user_id)
    if user is None:
        return False, False
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if user["password"] == hashed_password:
        is_admin = (user["is_admin"] == "TRUE" or user["is_admin"] == True)
        return True, is_admin
    return False, False

def update_user_id(sheet, old_id, new_id):
    try:
        worksheet = sheet.worksheet("users")
        users_data = pd.DataFrame(worksheet.get_all_records())
        if new_id in users_data["user_id"].values:
            return False, "新しいユーザーIDは既に存在します。"
        users_data.loc[users_data["user_id"] == old_id, "user_id"] = new_id
        worksheet.clear()
        worksheet.update([users_data.columns.tolist()] + users_data.values.tolist())

        weight_worksheet = sheet.worksheet("weight_data")
        weight_data = pd.DataFrame(weight_worksheet.get_all_records())
        if not weight_data.empty:
            weight_data.loc[weight_data["user_id"] == old_id, "user_id"] = new_id
            weight_worksheet.clear()
            weight_worksheet.update([weight_data.columns.tolist()] + weight_data.values.tolist())

        return True, "ユーザーIDが正常に更新されました。"
    except Exception as e:
        log_error("ユーザーID更新中にエラーが発生しました", e)
        return False, "ユーザーIDの更新に失敗しました。"

####################################
# 7. UI関連の関数
####################################

def show_login_page():
    st.markdown("<h1 class='title-text'>リコア - 体重管理システム ログイン</h1>", unsafe_allow_html=True)
    st.markdown("<h2 class='subtitle-text'>ログイン</h2>", unsafe_allow_html=True)
    user_id = st.text_input("ユーザーID")
    password = st.text_input("パスワード", type="password")

    if st.button("ログイン"):
        users_data = st.session_state.users_data
        auth_success, is_admin = authenticate_user(users_data, user_id, password)
        if auth_success:
            user = get_user_by_id(users_data, user_id)
            st.session_state.authenticated = True
            st.session_state.user_id = user_id
            st.session_state.user_name = user["name"]
            st.session_state.user_birth = user["birth_date"]
            st.session_state.is_admin = is_admin
            st.session_state.view_user_id = user_id
            st.session_state.message = "ログインに成功しました。"
            st.session_state.message_type = "success"
            st.session_state.page = "main"
            st.stop()
        else:
            st.error("ユーザーIDまたはパスワードが正しくありません。")

    if st.button("新規登録はこちら"):
        st.session_state.page = "register"
        st.stop()

def show_register_form():
    st.markdown("<h1 class='title-text'>新規ユーザー登録</h1>", unsafe_allow_html=True)
    user_id = st.text_input("ユーザーID（半角英数字）", key="reg_user_id")
    user_name = st.text_input("名前（カタカナのみ）", key="reg_user_name")
    height = st.number_input("身長 (cm)", min_value=50.0, max_value=250.0, value=170.0, step=0.1, key="reg_height")
    birth_date = st.date_input("生年月日", key="reg_birth_date")
    password = st.text_input("パスワード", type="password", key="reg_password")
    password_confirm = st.text_input("パスワード（確認）", type="password", key="reg_password_confirm")

    if st.button("登録"):
        if not user_id or not user_name or not password:
            st.error("すべての項目を入力してください。")
            return
        if not re.match(r'^[a-zA-Z0-9]+$', user_id):
            st.error("ユーザーIDは半角英数字のみ使用できます。")
            return
        if not re.match(r'^[ァ-ヶー]+$', user_name):
            st.error("名前はカタカナのみ使用できます。")
            return
        if password != password_confirm:
            st.error("パスワードが一致しません。")
            return
        if not st.session_state.users_data.empty and user_id in st.session_state.users_data["user_id"].values:
            st.error("このユーザーIDは既に使用されています。")
            return

        birth_str = birth_date.strftime("%Y-%m-%d")
        user_data = {
            "user_id": user_id,
            "name": user_name,
            "birth_date": birth_str,
            "password": password,
            "height": height,
            "is_admin": "FALSE"
        }
        sheet = setup_google_sheets()
        if sheet:
            if add_user(sheet, user_data):
                st.session_state.users_data = load_users_data(sheet)
                st.success("ユーザー登録が完了しました。ログインしてください。")
                st.session_state.page = "login"
                st.stop()
            else:
                st.error("ユーザー登録に失敗しました。")

    if st.button("戻る"):
        st.session_state.page = "login"
        st.stop()

def show_weight_input_form():
    st.markdown("<h2 class='subtitle-text'>新しい体重データを追加</h2>", unsafe_allow_html=True)
    col_date, col_weight = st.columns([4,3])
    with col_date:
        date = st.date_input("日付", value=datetime.now())
    with col_weight:
        weight = st.number_input("体重 (kg)", min_value=0.0, max_value=300.0, step=0.1)
    body_fat = st.number_input("体脂肪率 (%)", min_value=0.0, max_value=100.0, step=0.1)

    fat_mass = weight * (body_fat / 100)
    lean_mass = weight - fat_mass
    st.markdown(f"体脂肪量: **{fat_mass:.1f} kg**")
    st.markdown(f"除脂肪体重: **{lean_mass:.1f} kg**")

    if st.button("データを追加"):
        date_str = date.strftime("%Y-%m-%d")
        weight_data_dict = {
            "user_id": st.session_state.view_user_id,
            "date": date_str,
            "weight": weight,
            "body_fat": body_fat
        }
        sheet = setup_google_sheets()
        if sheet:
            if add_weight_data(sheet, weight_data_dict):
                st.session_state.weight_data = load_weight_data(sheet)
                st.session_state.message = "体重データを追加しました。"
                st.session_state.message_type = "success"
                st.stop()
            else:
                st.error("体重データの追加に失敗しました。")

####################################
# 8. メインページ (ダッシュボード等)
####################################

def show_dashboard():
    st.markdown("<h1 class='title-text'>ダッシュボード</h1>", unsafe_allow_html=True)
    # 選択期間
    period_sel = st.session_state.get("period_selection", "すべて")

    # ★★★ ここを修正して「ユーザーの名前」を表示するドロップダウンに変更 ★★★
    if st.session_state.is_admin:
        # users_data 全体から name -> user_id の辞書を作成
        name_to_id = {
            row["name"]: row["user_id"]
            for _, row in st.session_state.users_data.iterrows()
        }

        # 現在の view_user_id に該当する "name" を探す
        current_name = None
        for name, uid in name_to_id.items():
            if uid == st.session_state.view_user_id:
                current_name = name
                break
        # もし現在の view_user_id が見つからない場合は、最初のユーザーを選択
        if current_name is None and len(name_to_id) > 0:
            current_name = list(name_to_id.keys())[0]

        # ドロップダウンに「ユーザーの名前」を表示し、選択後は user_id を取り出す
        selected_name = st.selectbox(
            "ユーザーを選択",
            options=list(name_to_id.keys()),
            index=list(name_to_id.keys()).index(current_name) if current_name else 0
        )
        # 選択したユーザー名に対応する user_id をセット
        st.session_state.view_user_id = name_to_id[selected_name]

    user_data = get_user_by_id(st.session_state.users_data, st.session_state.view_user_id)
    if user_data is None:
        st.error("ユーザー情報が見つかりません。")
        return

    # 指定期間の weight データを抽出
    user_weights = st.session_state.weight_data[
        st.session_state.weight_data["user_id"] == st.session_state.view_user_id
    ]
    if period_sel != "すべて":
        today = datetime.now()
        if period_sel == "過去1週間":
            cutoff = today - timedelta(days=7)
        elif period_sel == "過去1ヶ月":
            cutoff = today - timedelta(days=30)
        elif period_sel == "過去3ヶ月":
            cutoff = today - timedelta(days=90)
        elif period_sel == "過去6ヶ月":
            cutoff = today - timedelta(days=180)
        elif period_sel == "過去1年":
            cutoff = today - timedelta(days=365)
        user_weights = user_weights[user_weights["date"] >= cutoff]

    if user_weights.empty:
        st.info("指定期間内に体重データがありません。")
        if st.session_state.is_admin:
            show_weight_input_form()
        return

    baseline = user_weights.sort_values("date").iloc[0]
    latest = user_weights.sort_values("date", ascending=False).iloc[0]
    weight_change = latest["weight"] - baseline["weight"]
    body_fat_change = latest["body_fat"] - baseline["body_fat"]
    fat_mass_change = latest["fat_mass"] - baseline["fat_mass"]
    lean_mass_change = latest["lean_mass"] - baseline["lean_mass"]

    st.markdown("<h2 class='subtitle-text'>体重データサマリー</h2>", unsafe_allow_html=True)
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("現在の体重", f"{latest['weight']:.1f} kg", f"{weight_change:+.1f} kg")
    with col2:
        st.metric("体脂肪率", f"{latest['body_fat']:.1f} %", f"{body_fat_change:+.1f} %")
    with col3:
        st.metric("体脂肪量", f"{latest['fat_mass']:.1f} kg", f"{fat_mass_change:+.1f} kg")
    with col4:
        st.metric("除脂肪体重", f"{latest['lean_mass']:.1f} kg", f"{lean_mass_change:+.1f} kg")
    with col5:
        height_cm = float(user_data.get("height", 170))
        bmi = latest["weight"] / ((height_cm/100) ** 2)
        st.metric("BMI", f"{bmi:.1f}")

    st.markdown("---")
    st.markdown("<h2 class='subtitle-text'>推移グラフ</h2>", unsafe_allow_html=True)
    filtered_weights = st.session_state.weight_data[
        st.session_state.weight_data["user_id"] == st.session_state.view_user_id
    ]
    if period_sel != "すべて":
        filtered_weights = filtered_weights[filtered_weights["date"] >= cutoff]

    graph_type = st.selectbox("グラフの種類", ["体重", "体脂肪率", "体脂肪量", "除脂肪体重", "すべて表示"], key="graph_type")
    if graph_type == "体重":
        fig = px.line(filtered_weights, x="date", y="weight", title="体重の推移", markers=True)
        fig.update_layout(xaxis_title="日付", yaxis_title="体重 (kg)")
        fig.update_xaxes(tickformat="%Y-%m-%d")
        st.plotly_chart(fig, use_container_width=True)
    elif graph_type == "体脂肪率":
        fig = px.line(filtered_weights, x="date", y="body_fat", title="体脂肪率の推移", markers=True)
        fig.update_layout(xaxis_title="日付", yaxis_title="体脂肪率 (%)")
        fig.update_xaxes(tickformat="%Y-%m-%d")
        st.plotly_chart(fig, use_container_width=True)
    elif graph_type == "体脂肪量":
        fig = px.line(filtered_weights, x="date", y="fat_mass", title="体脂肪量の推移", markers=True)
        fig.update_layout(xaxis_title="日付", yaxis_title="体脂肪量 (kg)")
        fig.update_xaxes(tickformat="%Y-%m-%d")
        st.plotly_chart(fig, use_container_width=True)
    elif graph_type == "除脂肪体重":
        fig = px.line(filtered_weights, x="date", y="lean_mass", title="除脂肪体重の推移", markers=True)
        fig.update_layout(xaxis_title="日付", yaxis_title="除脂肪体重 (kg)")
        fig.update_xaxes(tickformat="%Y-%m-%d")
        st.plotly_chart(fig, use_container_width=True)
    elif graph_type == "すべて表示":
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=filtered_weights["date"], y=filtered_weights["weight"], mode='lines+markers', name='体重 (kg)'))
        fig.add_trace(go.Scatter(x=filtered_weights["date"], y=filtered_weights["body_fat"], mode='lines+markers', name='体脂肪率 (%)'))
        fig.add_trace(go.Scatter(x=filtered_weights["date"], y=filtered_weights["fat_mass"], mode='lines+markers', name='体脂肪量 (kg)'))
        fig.add_trace(go.Scatter(x=filtered_weights["date"], y=filtered_weights["lean_mass"], mode='lines+markers', name='除脂肪体重 (kg)'))
        fig.update_layout(title="全データの推移", xaxis_title="日付", yaxis_title="値",
                          legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
        fig.update_xaxes(tickformat="%Y-%m-%d")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.markdown("<h2 class='subtitle-text'>記録データ</h2>", unsafe_allow_html=True)
    show_data = filtered_weights.copy()
    show_data["date"] = show_data["date"].dt.strftime("%Y-%m-%d")
    show_data = show_data.sort_values("date", ascending=False)
    show_data = show_data.rename(columns={
        "date": "日付",
        "weight": "体重 (kg)",
        "body_fat": "体脂肪率 (%)",
        "fat_mass": "体脂肪量 (kg)",
        "lean_mass": "除脂肪体重 (kg)"
    })
    show_data = show_data.drop(columns=["user_id"])
    for col in ["体重 (kg)", "体脂肪率 (%)", "体脂肪量 (kg)", "除脂肪体重 (kg)"]:
        show_data[col] = show_data[col].round(1)
    st.dataframe(show_data, use_container_width=True)

    if st.session_state.is_admin:
        st.markdown("---")
        show_weight_input_form()

def show_rankings():
    st.markdown("<h1 class='title-text'>ランキング</h1>", unsafe_allow_html=True)
    period_sel = st.session_state.get("period_selection", "すべて")
    rankings = calculate_rankings_period(st.session_state.weight_data, st.session_state.users_data, period_sel)
    tabs = st.tabs(["体重減少幅", "体重減少率", "除脂肪体重増加"])

    with tabs[0]:
        st.markdown("<h2 class='subtitle-text'>体重減少幅 (kg)</h2>", unsafe_allow_html=True)
        if not rankings["weight_loss"]:
            st.info("該当期間内に体重減少したユーザーはありません。")
        else:
            data = []
            for i, r in enumerate(rankings["weight_loss"], start=1):
                data.append({"順位": i, "ユーザーID": r["user_id"], "減少幅 (kg)": round(r["value"],1)})
            df = pd.DataFrame(data)
            st.table(df)

    with tabs[1]:
        st.markdown("<h2 class='subtitle-text'>体重減少率 (%)</h2>", unsafe_allow_html=True)
        if not rankings["weight_loss_rate"]:
            st.info("該当期間内に体重減少したユーザーはありません。")
        else:
            data = []
            for i, r in enumerate(rankings["weight_loss_rate"], start=1):
                data.append({"順位": i, "ユーザーID": r["user_id"], "減少率 (%)": round(r["value"],1)})
            df = pd.DataFrame(data)
            st.table(df)

    with tabs[2]:
        st.markdown("<h2 class='subtitle-text'>除脂肪体重増加 (kg)</h2>", unsafe_allow_html=True)
        if not rankings["lean_mass_increase"]:
            st.info("該当期間内に除脂肪体重が増加したユーザーはありません。")
        else:
            data = []
            for i, r in enumerate(rankings["lean_mass_increase"], start=1):
                data.append({"順位": i, "ユーザーID": r["user_id"], "増加量 (kg)": round(r["value"],1)})
            df = pd.DataFrame(data)
            st.table(df)

def show_settings():
    st.markdown("<h1 class='title-text'>設定</h1>", unsafe_allow_html=True)
    user_data = get_user_by_id(st.session_state.users_data, st.session_state.user_id)
    if user_data is None:
        st.error("ユーザー情報が見つかりません。")
        return

    st.markdown("<h2 class='subtitle-text'>ユーザー情報</h2>", unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"**現在のユーザーID**: {user_data['user_id']}")
    with col2:
        st.markdown(f"**名前**: {user_data['name']}")
    with col3:
        st.markdown(f"**生年月日**: {user_data['birth_date']}")
    with col4:
        st.markdown(f"**登録日**: {user_data['register_date']}")
    st.markdown(f"**身長**: {user_data.get('height', '不明')} cm")

    st.markdown("---")
    st.markdown("<h2 class='subtitle-text'>ユーザー情報の更新</h2>", unsafe_allow_html=True)
    update_col1, update_col2, update_col3, update_col4 = st.columns(4)
    with update_col1:
        new_user_id = st.text_input("新しいユーザーID", value=user_data["user_id"])
    with update_col2:
        new_name = st.text_input("名前（カタカナのみ）", value=user_data["name"])
    with update_col3:
        new_birth = st.date_input("生年月日", value=datetime.strptime(user_data["birth_date"], "%Y-%m-%d").date())
    with update_col4:
        new_height = st.number_input("身長 (cm)", min_value=50.0, max_value=250.0, value=float(user_data.get("height", 170)), step=0.1)

    st.markdown("---")
    st.markdown("<h2 class='subtitle-text'>パスワード変更</h2>", unsafe_allow_html=True)
    pwd_col1, pwd_col2, pwd_col3 = st.columns(3)
    with pwd_col1:
        current_pwd = st.text_input("現在のパスワード", type="password")
    with pwd_col2:
        new_pwd = st.text_input("新しいパスワード", type="password")
    with pwd_col3:
        confirm_pwd = st.text_input("新しいパスワード（確認）", type="password")

    if st.button("情報を更新"):
        sheet = setup_google_sheets()
        if sheet:
            # ユーザーIDを変更した場合
            if new_user_id != user_data["user_id"]:
                success, msg = update_user_id(sheet, user_data["user_id"], new_user_id)
                if success:
                    st.session_state.user_id = new_user_id
                    st.session_state.view_user_id = new_user_id
                    st.session_state.users_data = load_users_data(sheet)
                    st.success(msg)
                else:
                    st.error(msg)
                    return

            update_data = {}
            if new_name != user_data["name"]:
                if not re.match(r'^[ァ-ヶー]+$', new_name):
                    st.error("名前はカタカナのみ使用できます。")
                    return
                update_data["name"] = new_name

            new_birth_str = new_birth.strftime("%Y-%m-%d")
            if new_birth_str != user_data["birth_date"]:
                update_data["birth_date"] = new_birth_str

            if new_height != float(user_data.get("height", 170)):
                update_data["height"] = new_height

            if current_pwd and new_pwd:
                hashed_current = hashlib.sha256(current_pwd.encode()).hexdigest()
                if hashed_current != user_data["password"]:
                    st.error("現在のパスワードが正しくありません。")
                    return
                elif new_pwd != confirm_pwd:
                    st.error("新しいパスワードが一致しません。")
                    return
                else:
                    update_data["password"] = new_pwd

            if update_data:
                if update_user(sheet, st.session_state.user_id, update_data):
                    st.session_state.users_data = load_users_data(sheet)
                    if "name" in update_data:
                        st.session_state.user_name = update_data["name"]
                    if "birth_date" in update_data:
                        st.session_state.user_birth = update_data["birth_date"]
                    st.success("ユーザー情報が更新されました。")
                    st.stop()
                else:
                    st.error("ユーザー情報の更新に失敗しました。")
            else:
                st.info("更新する項目はありません。")

def show_admin_page():
    st.markdown("<h1 class='title-text'>管理者メニュー</h1>", unsafe_allow_html=True)
    tabs = st.tabs(["ユーザー管理", "体重データ管理"])

    with tabs[0]:
        st.markdown("<h2 class='subtitle-text'>ユーザー管理</h2>", unsafe_allow_html=True)
        st.markdown("#### ユーザー一覧")

        users_data = st.session_state.users_data.copy()
        if "is_admin" in users_data.columns:
            users_data["is_admin"] = users_data["is_admin"].apply(lambda x: "管理者" if x == "TRUE" or x == True else "一般ユーザー")
            users_data = users_data.rename(columns={"is_admin": "権限"})
        users_data = users_data.rename(columns={
            "user_id": "ユーザーID",
            "name": "名前",
            "birth_date": "生年月日",
            "password": "パスワード",
            "register_date": "登録日",
            "height": "身長 (cm)"
        })
        st.dataframe(users_data, use_container_width=True)

        st.markdown("<h2 class='subtitle-text'>選択ユーザーのパスワード更新</h2>", unsafe_allow_html=True)
        users_list = st.session_state.users_data["user_id"].tolist()
        users_dict = {uid: uid for uid in users_list}
        selected_user = st.selectbox("パスワード更新対象ユーザーを選択", options=list(users_dict.keys()), key="admin_pw_user_select")
        new_password = st.text_input("新しいパスワード", key="admin_new_password")

        if st.button("パスワード更新", key="update_password_button"):
            if new_password:
                sheet = setup_google_sheets()
                if sheet:
                    if update_user(sheet, selected_user, {"password": new_password}):
                        st.session_state.users_data = load_users_data(sheet)
                        st.session_state.message = "パスワードが更新されました。"
                        st.session_state.message_type = "success"
                        st.stop()
                    else:
                        st.error("パスワード更新に失敗しました。")
            else:
                st.error("新しいパスワードを入力してください。")

        st.markdown("---")
        st.markdown("<h2 class='subtitle-text'>新規ユーザー追加</h2>", unsafe_allow_html=True)
        user_id = st.text_input("ユーザーID（半角英数字）", key="admin_user_id")
        user_name = st.text_input("名前（カタカナのみ）", key="admin_name")
        height = st.number_input("身長 (cm)", min_value=50.0, max_value=250.0, value=170.0, step=0.1, key="admin_height")
        birth_date = st.date_input("生年月日", key="admin_birth")
        password = st.text_input("パスワード", type="password", key="admin_password")
        is_admin = st.checkbox("管理者権限を付与", key="admin_is_admin")

        if st.button("ユーザーを追加", key="add_user_button"):
            if not user_id or not user_name or not password:
                st.error("すべての項目を入力してください。")
            else:
                if not re.match(r'^[a-zA-Z0-9]+$', user_id):
                    st.error("ユーザーIDは半角英数字のみ使用できます。")
                elif not re.match(r'^[ァ-ヶー]+$', user_name):
                    st.error("名前はカタカナのみ使用できます。")
                elif not st.session_state.users_data.empty and user_id in st.session_state.users_data["user_id"].values:
                    st.error("このユーザーIDは既に使用されています。")
                else:
                    birth_str = birth_date.strftime("%Y-%m-%d")
                    user_data_dict = {
                        "user_id": user_id,
                        "name": user_name,
                        "birth_date": birth_str,
                        "password": password,
                        "height": height
                    }
                    sheet = setup_google_sheets()
                    if sheet:
                        if add_user(sheet, user_data_dict):
                            if is_admin:
                                update_user(sheet, user_id, {"is_admin": "TRUE"})
                            st.session_state.users_data = load_users_data(sheet)
                            st.session_state.message = "ユーザーを追加しました。"
                            st.session_state.message_type = "success"
                            st.stop()
                        else:
                            st.error("ユーザー追加に失敗しました。")

        st.markdown("---")
        st.markdown("<h2 class='subtitle-text'>ユーザー削除</h2>", unsafe_allow_html=True)
        users_list = st.session_state.users_data["user_id"].tolist()
        users_dict = {uid: uid for uid in users_list}
        # 自分自身は削除リストから除外
        if st.session_state.user_id in users_dict:
            del users_dict[st.session_state.user_id]
        if not users_dict:
            st.info("削除可能なユーザーがいません。")
        else:
            selected_user = st.selectbox("削除するユーザーを選択", options=list(users_dict.keys()), key="delete_user_select")
            if st.button("ユーザーを削除", key="delete_user_button"):
                confirm = st.checkbox("削除を確認しました", key="confirm_delete")
                if not confirm:
                    st.error("削除確認のチェックを入れてください。")
                else:
                    sheet = setup_google_sheets()
                    if sheet:
                        if delete_user(sheet, selected_user):
                            st.session_state.users_data = load_users_data(sheet)
                            st.session_state.weight_data = load_weight_data(sheet)
                            st.session_state.message = "ユーザーを削除しました。"
                            st.session_state.message_type = "success"
                            st.stop()
                        else:
                            st.error("ユーザー削除に失敗しました。")

    with tabs[1]:
        st.markdown("<h2 class='subtitle-text'>体重データ管理</h2>", unsafe_allow_html=True)
        users_list = st.session_state.users_data["user_id"].tolist()
        users_dict = {uid: uid for uid in users_list}
        selected_user = st.selectbox("ユーザーを選択", options=list(users_dict.keys()), key="admin_data_user_select")

        st.markdown("---")
        st.markdown("<h2 class='subtitle-text'>体重データ入力</h2>", unsafe_allow_html=True)
        col_date, col_weight = st.columns([4,3])
        with col_date:
            date = st.date_input("日付", value=datetime.now(), key="admin_data_date")
        with col_weight:
            weight = st.number_input("体重 (kg)", min_value=0.0, max_value=300.0, step=0.1, key="admin_data_weight")

        col_bodyfat, _ = st.columns([3,1])
        with col_bodyfat:
            body_fat = st.number_input("体脂肪率 (%)", min_value=0.0, max_value=100.0, step=0.1, key="admin_data_body_fat")

        fat_mass = weight * (body_fat / 100)
        lean_mass = weight - fat_mass
        st.markdown(f"体脂肪量: **{fat_mass:.1f} kg**")
        st.markdown(f"除脂肪体重: **{lean_mass:.1f} kg**")

        if st.button("データを追加", key="admin_data_add_button"):
            date_str = date.strftime("%Y-%m-%d")
            weight_data_dict = {
                "user_id": selected_user,
                "date": date_str,
                "weight": weight,
                "body_fat": body_fat
            }
            sheet = setup_google_sheets()
            if sheet:
                if add_weight_data(sheet, weight_data_dict):
                    st.session_state.weight_data = load_weight_data(sheet)
                    st.session_state.message = "体重データを追加しました。"
                    st.session_state.message_type = "success"
                    st.stop()
                else:
                    st.error("体重データの追加に失敗しました。")

        st.markdown("---")
        st.markdown("<h2 class='subtitle-text'>登録済みデータ</h2>", unsafe_allow_html=True)
        user_weights = st.session_state.weight_data[st.session_state.weight_data["user_id"] == selected_user]
        if user_weights.empty:
            st.info("体重データがまだ記録されていません。")
        else:
            show_data = user_weights.copy()
            show_data["date"] = show_data["date"].dt.strftime("%Y-%m-%d")
            show_data = show_data.sort_values("date", ascending=False)
            show_data = show_data.rename(columns={
                "date": "日付",
                "weight": "体重 (kg)",
                "body_fat": "体脂肪率 (%)",
                "fat_mass": "体脂肪量 (kg)",
                "lean_mass": "除脂肪体重 (kg)"
            })
            show_data = show_data.drop(columns=["user_id"])
            for col in ["体重 (kg)", "体脂肪率 (%)", "体脂肪量 (kg)", "除脂肪体重 (kg)"]:
                show_data[col] = show_data[col].round(1)
            st.dataframe(show_data, use_container_width=True)

####################################
# 9. メイン処理
####################################

def show_main_page():
    # サイドバーにて期間を選択
    period_sel = st.sidebar.selectbox(
        "期間選択",
        ["すべて", "過去1週間", "過去1ヶ月", "過去3ヶ月", "過去6ヶ月", "過去1年"],
        key="period_selection"
    )
    with st.sidebar:
        st.markdown(f'### ようこそ、{st.session_state.user_name}さん')
        menu_options = ["ダッシュボード", "ランキング", "設定"]
        if st.session_state.is_admin:
            menu_options.append("管理者メニュー")
        menu = st.radio("メニュー", menu_options)

        if st.button("ログアウト"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.session_state.message = "ログアウトしました。"
            st.session_state.message_type = "success"
            st.session_state.page = "login"
            st.stop()

    if st.session_state.message:
        message_style = "success-message" if st.session_state.message_type == "success" else "error-message"
        st.markdown(f'<div class="{message_style}">{st.session_state.message}</div>', unsafe_allow_html=True)
        st.session_state.message = ""
        st.session_state.message_type = ""

    # メニュー画面遷移
    if menu == "ダッシュボード":
        show_dashboard()
    elif menu == "ランキング":
        show_rankings()
    elif menu == "設定":
        show_settings()
    elif menu == "管理者メニュー" and st.session_state.is_admin:
        show_admin_page()

def main():
    try:
        sheet = setup_google_sheets()
        if sheet:
            if st.session_state.users_data.empty:
                st.session_state.users_data = load_users_data(sheet)
            if st.session_state.weight_data.empty:
                st.session_state.weight_data = load_weight_data(sheet)

        if st.session_state.page == "login":
            show_login_page()
        elif st.session_state.page == "register":
            show_register_form()
        elif st.session_state.page == "main":
            show_main_page()
        else:
            st.session_state.page = "login"
            st.stop()

    except Exception as e:
        log_error("アプリケーション実行中にエラーが発生しました", e)
        st.error(f"エラーが発生しました: {str(e)}")
        st.error("詳細はログを確認してください。")

if __name__ == "__main__":
    main()

st.markdown("""
<div class="footer">
    <p>リコア体重管理システム © 2025</p>
</div>
""", unsafe_allow_html=True)

def list_sheet_titles(sheet):
    titles = [ws.title for ws in sheet.worksheets()]
    st.write("利用可能なシート名:", titles)
