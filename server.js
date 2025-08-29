require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cron = require('node-cron');

const app = express();
app.use(bodyParser.raw({ type: 'application/json' }));

// FileMaker認証トークンの管理
let fmToken = null;
let tokenExpiryTime = null;

// FileMakerクラス
class FileMakerAPI {
    constructor() {
        this.baseURL = `${process.env.FM_SERVER_URL}/fmi/data/v2`;
        this.database = process.env.FM_DATABASE;
        this.layout = process.env.FM_LAYOUT;
    }

    async login() {
        try {
            console.log('Attempting FileMaker login...');
            
            const response = await axios.post(
                `${this.baseURL}/databases/${this.database}/sessions`,
                {},
                {
                    auth: {
                        username: process.env.FM_USERNAME,
                        password: process.env.FM_PASSWORD
                    },
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            fmToken = response.headers['x-fm-data-access-token'];
            tokenExpiryTime = Date.now() + (14 * 60 * 1000);
            
            console.log('FileMaker login successful');
            return fmToken;
        } catch (error) {
            console.error('FileMaker login error:', error.response?.data || error.message);
            throw error;
        }
    }

    async ensureValidToken() {
        if (!fmToken || Date.now() >= tokenExpiryTime) {
            await this.login();
        }
        return fmToken;
    }

    async createRecord(fieldData) {
        try {
            await this.ensureValidToken();

            const response = await axios.post(
                `${this.baseURL}/databases/${this.database}/layouts/${this.layout}/records`,
                {
                    fieldData: fieldData,
                    options: {
                        entrymode: "user",
                        prohibitmode: "user"
                    }
                },
                {
                    headers: {
                        'Authorization': `Bearer ${fmToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            console.log('Record created successfully:', response.data.response);
            return response.data;
        } catch (error) {
            if (error.response?.status === 401) {
                console.log('Token expired, re-authenticating...');
                await this.login();
                return this.createRecord(fieldData);
            }
            
            console.error('FileMaker create record error:', error.response?.data || error.message);
            throw error;
        }
    }

    async findRecord(callId) {
        try {
            await this.ensureValidToken();

            const response = await axios.post(
                `${this.baseURL}/databases/${this.database}/layouts/${this.layout}/_find`,
                {
                    query: [{
                        "call_id": callId
                    }],
                    limit: 1
                },
                {
                    headers: {
                        'Authorization': `Bearer ${fmToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            return response.data.response.data;
        } catch (error) {
            if (error.response?.data?.messages?.[0]?.code === "401") {
                return [];
            }
            throw error;
        }
    }

    async updateRecord(recordId, fieldData, modId = null) {
        try {
            await this.ensureValidToken();

            const requestBody = { fieldData };
            if (modId) {
                requestBody.modId = modId;
            }

            const response = await axios.patch(
                `${this.baseURL}/databases/${this.database}/layouts/${this.layout}/records/${recordId}`,
                requestBody,
                {
                    headers: {
                        'Authorization': `Bearer ${fmToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            console.log('Record updated successfully');
            return response.data;
        } catch (error) {
            if (error.response?.status === 401) {
                await this.login();
                return this.updateRecord(recordId, fieldData, modId);
            }
            
            console.error('FileMaker update record error:', error.response?.data || error.message);
            throw error;
        }
    }

    async logout() {
        if (!fmToken) return;

        try {
            await axios.delete(
                `${this.baseURL}/databases/${this.database}/sessions/${fmToken}`,
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
            
            fmToken = null;
            tokenExpiryTime = null;
            console.log('FileMaker logout successful');
        } catch (error) {
            console.error('FileMaker logout error:', error.message);
        }
    }
}

const fm = new FileMakerAPI();

function verifyZoomWebhook(req) {
    const message = `v0:${req.headers['x-zm-request-timestamp']}:${req.body}`;
    const hashForVerify = crypto
        .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
        .update(message)
        .digest('hex');
    const signature = `v0=${hashForVerify}`;
    
    return signature === req.headers['x-zm-signature'];
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '';
    
    const date = new Date(timestamp);
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    return `${month}/${day}/${year} ${hours}:${minutes}:${seconds}`;
}

function formatDuration(seconds) {
    if (!seconds) return '00:00:00';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

// ルートエンドポイント
app.get('/', (req, res) => {
    res.json({ 
        status: 'running',
        service: 'Zoom-FileMaker Integration',
        timestamp: new Date().toISOString()
    });
});

// Webhookエンドポイント
app.post('/zoom-webhook', async (req, res) => {
    const body = JSON.parse(req.body);

    // CRC検証（初回設定時）
    if (body.event === 'endpoint.url_validation') {
        const hashForPlainToken = crypto
            .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
            .update(body.payload.plainToken)
            .digest('hex');

        return res.json({
            plainToken: body.payload.plainToken,
            encryptedToken: hashForPlainToken
        });
    }

    // Webhook署名検証
    if (!verifyZoomWebhook(req)) {
        console.error('Webhook verification failed');
        return res.status(401).send('Unauthorized');
    }

    try {
        const event = body.event;
        const payload = body.payload.object;
        
        console.log(`Processing event: ${event}`);

        let recordData = {};
        let shouldUpdate = false;
        let existingRecord = null;

        switch (event) {
            case 'phone.call_log_created':
            case 'phone.caller_call_log_completed':
            case 'phone.callee_call_log_completed':
                const callId = payload.call_id || payload.id;
                if (callId) {
                    const records = await fm.findRecord(callId);
                    if (records.length > 0) {
                        existingRecord = records[0];
                        shouldUpdate = true;
                    }
                }

                recordData = {
                    // 新規追加フィールド
                    call_id: callId,
                    call_duration_seconds: payload.duration || 0,
                    call_direction: payload.direction || '',
                    call_end_time: formatTimestamp(payload.end_time),
                    
                    // 既存フィールドへのマッピング
                    電話番号: payload.caller_number || payload.callee_number || '',
                    対応日時: formatTimestamp(payload.start_time || payload.date_time),
                    状態: '未対応'
                };
                break;

            case 'phone.callee_missed':
                recordData = {
                    // 新規追加フィールド
                    call_id: payload.call_id || payload.id,
                    call_duration_seconds: 0,
                    call_direction: 'inbound',
                    call_end_time: formatTimestamp(payload.date_time),
                    
                    // 既存フィールドへのマッピング
                    電話番号: payload.caller_number || '',
                    対応日時: formatTimestamp(payload.date_time),
                    状態: '未対応'
                };
                break;
        }

        if (Object.keys(recordData).length > 0) {
            if (shouldUpdate && existingRecord) {
                await fm.updateRecord(
                    existingRecord.recordId,
                    recordData,
                    existingRecord.modId
                );
                console.log(`Record updated for call_id: ${recordData.call_id || 'unknown'}`);
            } else {
                await fm.createRecord(recordData);
                console.log(`Record created for call_id: ${recordData.call_id || 'unknown'}`);
            }
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('Error processing webhook:', error);
        res.status(500).send('Internal Server Error');
    }
});

// ヘルスチェック
app.get('/health', async (req, res) => {
    try {
        await fm.ensureValidToken();
        res.json({ 
            status: 'healthy',
            timestamp: new Date().toISOString(),
            filemakerConnected: !!fmToken
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'unhealthy',
            error: error.message 
        });
    }
});

// トークンの定期更新（13分ごと）
cron.schedule('*/13 * * * *', async () => {
    console.log('Refreshing FileMaker token...');
    try {
        await fm.login();
    } catch (error) {
        console.error('Token refresh failed:', error.message);
    }
});

// グレースフルシャットダウン
process.on('SIGTERM', async () => {
    console.log('SIGTERM signal received: closing HTTP server');
    await fm.logout();
    process.exit(0);
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // 起動時にFileMakerにログイン
    try {
        await fm.login();
        console.log('Initial FileMaker connection established');
    } catch (error) {
        console.error('Initial FileMaker connection failed:', error.message);
    }
});