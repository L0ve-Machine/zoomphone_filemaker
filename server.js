import dotenv from 'dotenv';
import express from 'express';
import bodyParser from 'body-parser';
import { DataApi } from '@proofgeist/fmdapi';
import crypto from 'crypto';

dotenv.config();

const app = express();
app.use(bodyParser.raw({ type: 'application/json' }));

// FileMaker Cloud接続設定
const client = new DataApi({
    server: process.env.FM_SERVER_URL,
    database: process.env.FM_DATABASE,
    auth: {
        username: process.env.FM_USERNAME,
        password: process.env.FM_PASSWORD,
        type: 'FileMakerID' // Claris ID認証を使用
    },
    layout: process.env.FM_LAYOUT
});

// タイムスタンプ変換
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

// 通話時間フォーマット
function formatDuration(seconds) {
    if (!seconds) return '00:00:00';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

// Zoom Webhook検証
function verifyZoomWebhook(req) {
    const message = `v0:${req.headers['x-zm-request-timestamp']}:${req.body}`;
    const hashForVerify = crypto
        .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN || 'temp')
        .update(message)
        .digest('hex');
    const signature = `v0=${hashForVerify}`;
    
    return signature === req.headers['x-zm-signature'];
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
            .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN || 'temp')
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

        // イベントタイプごとの処理
        switch (event) {
            case 'phone.call_log_created':
            case 'phone.caller_call_log_completed':
            case 'phone.callee_call_log_completed':
                const callId = payload.call_id || payload.id;
                
                // 既存レコード検索
                try {
                    const existingRecords = await client.find({
                        query: [{ call_id: callId }]
                    });
                    
                    if (existingRecords.data && existingRecords.data.length > 0) {
                        console.log(`Record already exists for call_id: ${callId}`);
                        return res.status(200).send('OK - Record exists');
                    }
                } catch (err) {
                    // レコードが見つからない場合は新規作成
                }

                recordData = {
                    call_id: callId,
                    call_duration_seconds: payload.duration || 0,
                    call_direction: payload.direction || '',
                    call_end_time: formatTimestamp(payload.end_time),
                    電話番号: payload.caller_number || payload.callee_number || '',
                    対応日時: formatTimestamp(payload.start_time || payload.date_time),
                    状態: '未対応'
                };
                break;

            case 'phone.callee_missed':
                recordData = {
                    call_id: payload.call_id || payload.id,
                    call_duration_seconds: 0,
                    call_direction: 'inbound',
                    電話番号: payload.caller_number || '',
                    対応日時: formatTimestamp(payload.date_time),
                    状態: '未対応'
                };
                break;

            default:
                console.log(`Unhandled event type: ${event}`);
                return res.status(200).send('OK - Event not processed');
        }

        // FileMakerにレコード作成
        if (Object.keys(recordData).length > 0) {
            try {
                await client.create(recordData);
                console.log(`Record created for call_id: ${recordData.call_id || 'unknown'}`);
            } catch (error) {
                console.error('FileMaker create error:', error.message);
                // エラーが発生してもWebhookは成功として返す
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
        // FileMaker接続テスト
        const layouts = await client.layouts();
        res.json({ 
            status: 'healthy',
            timestamp: new Date().toISOString(),
            filemakerConnected: true,
            availableLayouts: layouts
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'unhealthy',
            error: error.message 
        });
    }
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // 起動時の接続テスト
    try {
        const layouts = await client.layouts();
        console.log('FileMaker Cloud connection established');
        console.log('Available layouts:', layouts);
    } catch (error) {
        console.error('Initial FileMaker connection failed:', error.message);
        console.error('Make sure 2FA is disabled for the API account');
    }
});