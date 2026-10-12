<?php
declare(strict_types=1);

const GUEST_DATA_DIR = __DIR__ . '/private';
const GUEST_USERS_FILE = GUEST_DATA_DIR . '/users.txt';

if (!is_dir(GUEST_DATA_DIR)) {
    http_response_code(500);
    exit('Не найден каталог private.');
}

ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_strict_mode', '1');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);

session_start();

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');

if (empty($_SESSION['guest_csrf'])) {
    $_SESSION['guest_csrf'] = bin2hex(random_bytes(32));
}

function guestJsonReply(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function guestRoomPath(string $room): string
{
    return GUEST_DATA_DIR . '/' . $room . '.json';
}

function guestValidRoom(string $room): bool
{
    return (bool) preg_match('/^[a-f0-9]{32}$/', $room);
}

function guestReadRoom(string $room): ?array
{
    $path = guestRoomPath($room);

    if (!is_file($path)) {
        return null;
    }

    $file = fopen($path, 'rb');

    if ($file === false) {
        return null;
    }

    flock($file, LOCK_SH);
    $contents = stream_get_contents($file);
    flock($file, LOCK_UN);
    fclose($file);

    if (!is_string($contents)) {
        return null;
    }

    $data = json_decode($contents, true);

    return is_array($data) ? $data : null;
}

function guestRequestInput(): array
{
    $input = json_decode((string) file_get_contents('php://input'), true);

    return is_array($input) ? $input : [];
}

function guestCheckKey(array $data, string $key): bool
{
    $storedHash = (string) ($data['key_hash'] ?? '');

    return $storedHash !== ''
        && $key !== ''
        && hash_equals($storedHash, hash('sha256', $key));
}

function guestCredentialsMatch(string $username, string $password): bool
{
    if (!is_file(GUEST_USERS_FILE)) {
        return false;
    }

    $lines = file(
        GUEST_USERS_FILE,
        FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
    );

    if ($lines === false) {
        return false;
    }

    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);

        if (
            count($parts) === 2
            && hash_equals($parts[0], $username)
            && password_verify($password, $parts[1])
        ) {
            return true;
        }
    }

    return false;
}

function guestBaseUrl(): string
{
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $scheme = $https ? 'https' : 'http';
    $host = (string) (
        $_SERVER['HTTP_HOST']
        ?? $_SERVER['SERVER_NAME']
        ?? 'localhost'
    );

    if (!preg_match('/^[a-zA-Z0-9.:\-\[\]]+$/', $host)) {
        $host = (string) ($_SERVER['SERVER_NAME'] ?? 'localhost');
    }

    return $scheme
        . '://'
        . $host
        . (string) ($_SERVER['SCRIPT_NAME'] ?? '/guest.php');
}

$action = (string) ($_GET['action'] ?? '');

if ($action !== '') {
    $input = guestRequestInput();
    $room = (string) ($input['room'] ?? $_GET['room'] ?? '');
    $key = (string) ($input['key'] ?? $_GET['key'] ?? '');

    if (!guestValidRoom($room)) {
        guestJsonReply(['error' => 'Некорректное имя чата'], 400);
    }

    $roomData = guestReadRoom($room);

    if ($roomData === null || !guestCheckKey($roomData, $key)) {
        guestJsonReply(
            ['error' => 'Чат не найден или ссылка недействительна'],
            404
        );
    }

    if ($action === 'messages' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        guestJsonReply([
            'messages' => is_array($roomData['messages'] ?? null)
                ? $roomData['messages']
                : [],
        ]);
    }

    if ($action === 'messages' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $iv = (string) ($input['iv'] ?? '');
        $ciphertext = (string) ($input['ciphertext'] ?? '');
        $sender = trim((string) ($input['sender'] ?? 'Гость'));

        $decodedIv = base64_decode($iv, true);
        $decodedCiphertext = base64_decode($ciphertext, true);

        if (
            $decodedIv === false
            || strlen($decodedIv) !== 12
            || $decodedCiphertext === false
            || strlen($decodedCiphertext) < 1
            || strlen($decodedCiphertext) > 12000000
        ) {
            guestJsonReply(
                ['error' => 'Некорректные данные сообщения'],
                400
            );
        }

        if ($sender === '') {
            $sender = 'Гость';
        }

        $sender = function_exists('mb_substr')
            ? mb_substr($sender, 0, 60, 'UTF-8')
            : substr($sender, 0, 60);

        $path = guestRoomPath($room);
        $file = fopen($path, 'c+');

        if ($file === false || !flock($file, LOCK_EX)) {
            if (is_resource($file)) {
                fclose($file);
            }

            guestJsonReply(
                ['error' => 'Не удалось сохранить сообщение'],
                500
            );
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $current = json_decode(
            is_string($contents) ? $contents : '',
            true
        );

        if (!is_array($current) || !guestCheckKey($current, $key)) {
            flock($file, LOCK_UN);
            fclose($file);

            guestJsonReply(
                ['error' => 'Чат удалён или ссылка недействительна'],
                404
            );
        }

        if (!isset($current['messages']) || !is_array($current['messages'])) {
            $current['messages'] = [];
        }

        $current['messages'][] = [
            'id' => bin2hex(random_bytes(16)),
            'sender' => $sender,
            'createdAt' => gmdate('c'),
            'iv' => $iv,
            'ciphertext' => $ciphertext,
        ];

        $encoded = json_encode(
            $current,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        if ($encoded === false) {
            flock($file, LOCK_UN);
            fclose($file);

            guestJsonReply(
                ['error' => 'Не удалось сохранить сообщение'],
                500
            );
        }

        rewind($file);
        ftruncate($file, 0);
        $written = fwrite($file, $encoded);
        fflush($file);
        flock($file, LOCK_UN);
        fclose($file);

        if ($written === false) {
            guestJsonReply(
                ['error' => 'Не удалось сохранить сообщение'],
                500
            );
        }

        guestJsonReply(['ok' => true]);
    }

    if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $path = guestRoomPath($room);
        $file = fopen($path, 'c+');

        if ($file === false || !flock($file, LOCK_EX)) {
            if (is_resource($file)) {
                fclose($file);
            }

            guestJsonReply(['error' => 'Не удалось удалить чат'], 500);
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $current = json_decode(
            is_string($contents) ? $contents : '',
            true
        );

        if (!is_array($current) || !guestCheckKey($current, $key)) {
            flock($file, LOCK_UN);
            fclose($file);

            guestJsonReply(
                ['error' => 'Чат уже удалён или ссылка недействительна'],
                404
            );
        }

        flock($file, LOCK_UN);
        fclose($file);

        if (!@unlink($path)) {
            guestJsonReply(['error' => 'Не удалось удалить чат'], 500);
        }

        guestJsonReply(['ok' => true]);
    }

    guestJsonReply(['error' => 'Неизвестный запрос'], 404);
}

$view = 'login';
$error = '';
$shareUrl = '';
$room = (string) ($_GET['room'] ?? '');
$key = (string) ($_GET['key'] ?? '');

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['form_action'] ?? '') === 'create'
) {
    $csrf = (string) ($_POST['csrf'] ?? '');

    if (!hash_equals((string) $_SESSION['guest_csrf'], $csrf)) {
        $error = 'Сессия формы устарела. Обновите страницу и попробуйте снова.';
    } else {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        if (
            !preg_match('/^[a-zA-Z0-9_.-]{1,40}$/', $username)
            || !guestCredentialsMatch($username, $password)
        ) {
            $error = 'Неверный логин или пароль.';
        } else {
            session_regenerate_id(true);

            try {
                $room = bin2hex(random_bytes(16));
                $key = bin2hex(random_bytes(32));

                $roomData = [
                    'key_hash' => hash('sha256', $key),
                    'messages' => [],
                    'created_at' => gmdate('c'),
                ];

                $json = json_encode(
                    $roomData,
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                );

                if (
                    $json === false
                    || file_put_contents(
                        guestRoomPath($room),
                        $json,
                        LOCK_EX
                    ) === false
                ) {
                    throw new RuntimeException(
                        'Не удалось создать файл чата.'
                    );
                }

                @chmod(guestRoomPath($room), 0600);
                $_SESSION['guest_owner_room'] = $room;

                $shareUrl = guestBaseUrl()
                    . '?room=' . rawurlencode($room)
                    . '&key=' . rawurlencode($key);

                $view = 'share';
            } catch (Throwable $exception) {
                error_log((string) $exception);
                $error = 'Не удалось создать чат. Проверьте права доступа к каталогу private.';
            }
        }
    }
}

if ($view !== 'share' && $room !== '') {
    $roomData = guestValidRoom($room)
        ? guestReadRoom($room)
        : null;

    if (
        $roomData !== null
        && $key !== ''
        && guestCheckKey($roomData, $key)
    ) {
        $view = 'chat';
    } else {
        $view = 'missing';
    }
}

$roomForJs = json_encode(
    $room,
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);

$keyForJs = json_encode(
    $key,
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);

$apiForJs = json_encode(
    (string) ($_SERVER['SCRIPT_NAME'] ?? '/guest.php'),
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>Зашифрованный чат</title>
    <link rel="stylesheet" href="web.css">
</head>
<body>
<main class="app">
    <header class="brand">
        <div class="brand-icon" aria-hidden="true">✦</div>
        <div>
            <h1>Зашифрованный чат</h1>
            <p>Сообщения шифруются в браузере</p>
        </div>
    </header>

    <?php if ($view === 'login'): ?>
        <section class="panel login-panel">
            <h2>Создать гостевой чат</h2>

            <form method="post" action="guest.php">
                <input type="hidden" name="form_action" value="create">
                <input
                    type="hidden"
                    name="csrf"
                    value="<?= htmlspecialchars(
                        (string) $_SESSION['guest_csrf'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>"
                >

                <label for="username">Логин</label>
                <input
                    id="username"
                    name="username"
                    autocomplete="username"
                    required
                >

                <label for="password">Пароль учётной записи</label>
                <input
                    id="password"
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >

                <?php if ($error !== ''): ?>
                    <p class="status" role="alert">
                        <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                    </p>
                <?php endif; ?>

                <button class="primary" type="submit">
                    Войти и создать чат
                </button>
            </form>
        </section>

<?php elseif ($view === 'share'): ?>
    <section class="panel login-panel">
        <h2>Чат создан</h2>

        <p class="hint">
            Сохраните ссылку и передайте её участникам. Она содержит ключ
            шифрования, необходимый для доступа к переписке.
        </p>

        <label for="shareLink">Ссылка на чат</label>
        <input
            id="shareLink"
            value="<?= htmlspecialchars($shareUrl, ENT_QUOTES, 'UTF-8') ?>"
            readonly
        >

        <button class="quiet" type="button" id="copyLinkButton">
            Копировать ссылку
        </button>

        <p id="copyStatus" class="status" role="status" aria-live="polite"></p>

        <button class="primary" type="button" id="continueButton">
            Продолжить в чат
        </button>
    </section>

    <script>
        const shareLink = document.getElementById('shareLink');
        const copyStatus = document.getElementById('copyStatus');

        document
            .getElementById('copyLinkButton')
            .addEventListener('click', async () => {
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(shareLink.value);
                    } else {
                        shareLink.focus();
                        shareLink.select();

                        if (!document.execCommand('copy')) {
                            throw new Error('Не удалось скопировать ссылку.');
                        }

                        shareLink.setSelectionRange(0, 0);
                    }

                    copyStatus.textContent = 'Ссылка скопирована.';
                } catch (error) {
                    copyStatus.textContent =
                        'Не удалось скопировать ссылку. Выделите её и скопируйте вручную.';
                }
            });

        document
            .getElementById('continueButton')
            .addEventListener('click', () => {
                window.location.href = shareLink.value;
            });
    </script>


    <?php elseif ($view === 'chat'): ?>
        <section class="panel chat-panel" id="chatBox">
            <header class="chat-header">
                <div>
                    <h2>Общий чат</h2>
                    <span class="security-label">
                        ● Шифрование включено
                    </span>
                </div>

                <div class="header-actions">
                    <button
                        id="refreshButton"
                        class="quiet"
                        type="button"
                        aria-label="Обновить сообщения"
                    >
                        ↻
                    </button>

                    <button id="deleteButton" class="quiet" type="button">
                        Удалить чат
                    </button>
                </div>
            </header>

            <div id="messages" class="messages" aria-live="polite"></div>

            <form id="messageForm" class="composer">
                <label for="senderName">Ваше имя</label>
                <input
                    id="senderName"
                    maxlength="60"
                    autocomplete="nickname"
                    value="Гость"
                >

                <label for="message">Сообщение</label>
                <textarea
                    id="message"
                    maxlength="10000"
                    placeholder="Напишите сообщение…"
                ></textarea>

                <button id="sendButton" class="primary" type="submit">
                    Зашифровать и отправить
                </button>

                <p class="hint">Ключ шифрования находится в ссылке чата.</p>
            </form>
        </section>

        <p id="status" class="status" role="status" aria-live="polite"></p>

        <script>
        'use strict';

        const ROOM = <?= $roomForJs ?>;
        const CHAT_KEY = <?= $keyForJs ?>;
        const API_ENDPOINT = <?= $apiForJs ?>;
        const PBKDF2_SALT = new TextEncoder().encode(
            'encrypted-chat-v1-global-salt'
        );
        const PBKDF2_ITERATIONS = 600000;

        const el = id => document.getElementById(id);

        let cryptoKey = null;
        let pollTimer = null;
        let loading = false;
        let lastSignature = null;

        function setStatus(message = '') {
            el('status').textContent = message;
        }

        function base64Encode(bytes) {
            let binary = '';

            for (const byte of bytes) {
                binary += String.fromCharCode(byte);
            }

            return btoa(binary);
        }

        function base64Decode(value) {
            const binary = atob(value);
            const bytes = new Uint8Array(binary.length);

            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            return bytes;
        }

        async function deriveEncryptionKey(passphrase) {
            const material = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(passphrase),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            return crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: PBKDF2_SALT,
                    iterations: PBKDF2_ITERATIONS,
                    hash: 'SHA-256'
                },
                material,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        }

        async function api(action, method = 'GET', body = null) {
            const url = new URL(API_ENDPOINT, window.location.href);
            url.searchParams.set('action', action);

            const options = {
                method,
                credentials: 'same-origin',
                headers: {}
            };

            if (method === 'GET') {
                url.searchParams.set('room', ROOM);
                url.searchParams.set('key', CHAT_KEY);
            } else {
                options.headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify({
                    room: ROOM,
                    key: CHAT_KEY,
                    ...(body || {})
                });
            }

            const response = await fetch(url, options);
            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                throw new Error(
                    data.error || `Ошибка запроса (${response.status})`
                );
            }

            return data;
        }

        function appendText(container, text) {
            const node = document.createElement('div');
            node.className = 'message-text';
            node.textContent = text;
            container.appendChild(node);
        }

        async function renderMessages() {
            if (loading) {
                return;
            }

            loading = true;

            try {
                const result = await api('messages');
                const records = Array.isArray(result.messages)
                    ? result.messages
                    : [];

                const signature = records
                    .map(record => record.id)
                    .join('|');

                if (signature === lastSignature) {
                    return;
                }

                lastSignature = signature;

                const container = el('messages');
                container.replaceChildren();

                let shown = 0;

                for (const record of records) {
                    try {
                        const plaintext = await crypto.subtle.decrypt(
                            {
                                name: 'AES-GCM',
                                iv: base64Decode(record.iv)
                            },
                            cryptoKey,
                            base64Decode(record.ciphertext)
                        );

                        const payload = JSON.parse(
                            new TextDecoder().decode(plaintext)
                        );

                        const card = document.createElement('article');
                        card.className = 'message';

                        const meta = document.createElement('div');
                        meta.className = 'message-meta';
                        meta.textContent =
                            `${record.sender || 'Гость'} · ` +
                            `${record.createdAt || ''}`;

                        card.appendChild(meta);
                        appendText(card, payload.text || '');
                        container.appendChild(card);
                        shown++;
                    } catch {
                        // Сообщение, которое не удалось расшифровать, пропускается.
                    }
                }

                if (!shown) {
                    const empty = document.createElement('p');
                    empty.className = 'empty-message';
                    empty.textContent = 'Пока нет сообщений.';
                    container.appendChild(empty);
                }

                container.scrollTop = container.scrollHeight;
            } finally {
                loading = false;
            }
        }

        async function sendMessage(event) {
            event.preventDefault();
            setStatus();

            const text = el('message').value;

            if (!text.trim()) {
                setStatus('Введите сообщение.');
                return;
            }

            try {
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const plaintext = new TextEncoder().encode(
                    JSON.stringify({ text })
                );

                const ciphertext = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv },
                    cryptoKey,
                    plaintext
                );

                await api('messages', 'POST', {
                    sender: el('senderName').value.trim() || 'Гость',
                    iv: base64Encode(iv),
                    ciphertext: base64Encode(new Uint8Array(ciphertext))
                });

                el('message').value = '';
                lastSignature = null;
                await renderMessages();
            } catch (error) {
                setStatus(error.message || String(error));
            }
        }

        async function deleteChat() {
            if (
                !window.confirm(
                    'Удалить чат и все сообщения? Это действие нельзя отменить.'
                )
            ) {
                return;
            }

            try {
                await api('delete', 'POST');
                stopPolling();
                el('chatBox').hidden = true;
                setStatus('Чат удалён.');
            } catch (error) {
                setStatus(error.message || String(error));
            }
        }

        function stopPolling() {
            if (pollTimer !== null) {
                clearInterval(pollTimer);
                pollTimer = null;
            }
        }

        el('messageForm').addEventListener('submit', sendMessage);
        el('deleteButton').addEventListener('click', deleteChat);

        el('refreshButton').addEventListener('click', async () => {
            lastSignature = null;

            try {
                await renderMessages();
            } catch (error) {
                setStatus(error.message || String(error));
            }
        });

        (async () => {
            try {
                cryptoKey = await deriveEncryptionKey(CHAT_KEY);
                await renderMessages();

                pollTimer = setInterval(() => {
                    renderMessages().catch(error => {
                        setStatus(error.message || String(error));
                    });
                }, 2000);
            } catch (error) {
                setStatus(error.message || String(error));
            }
        })();
        </script>

    <?php else: ?>
        <section class="panel login-panel">
            <h2>Чат недоступен</h2>
            <p class="hint">
                Чат не найден, уже удалён или ссылка недействительна.
            </p>
        </section>
    <?php endif; ?>
</main>
</body>
</html>
