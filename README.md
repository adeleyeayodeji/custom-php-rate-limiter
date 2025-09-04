# custom-php-rate-limiter
Secure your application with custom php rate limiter

```php

<?php

/**
 * Rate Limiter
 * 
 * @package RateLimiter
 * @author BiggiDroid
 * @version 1.0.0
 */
class RateLimiter
{
    /**
     * @var string $ip
     */
    private string $ip;

    /**
     * @var int $limit
     */
    private int $limit;

    /**
     * @var int $window
     */
    private int $window;

    /**
     * @var string $key
     */
    private string $key;

    /**
     * @param int $limit
     * @param int $window
     */
    public function __construct(int $limit = 10, int $window = 60)
    {
        $this->ip     = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $this->limit  = $limit;
        $this->window = $window;
        $this->key    = "ratelimit_" . hash('sha256', $this->ip);
    }

    /**
     * @return bool
     */
    public function check(): bool
    {
        $now = time();
        $data = apcu_fetch($this->key);

        if ($data === false) {
            // First request: initialize counter
            $data = ['count' => 1, 'expires_at' => $now + $this->window];
            apcu_store($this->key, $data, $this->window);
            return true;
        }

        $count     = $data['count'];
        $expiresAt = $data['expires_at'];

        // Reset if window expired
        if ($now > $expiresAt) {
            $data = ['count' => 1, 'expires_at' => $now + $this->window];
            apcu_store($this->key, $data, $this->window);
            return true;
        }

        // Check if limit exceeded
        if ($count >= $this->limit) {
            //deny request
            $this->deny($expiresAt - $now);
            return false;
        }

        // Increment request count
        $data['count']++;
        apcu_store($this->key, $data, $expiresAt - $now);

        return true;
    }

    /**
     * @param int $retryAfter
     * @return void
     */
    private function deny(int $retryAfter): void
    {
        http_response_code(429);
        header('Retry-After: ' . $retryAfter);
        header('Content-Type: application/json');
        echo json_encode([
            'status'      => 'error',
            'message'     => 'Rate limit exceeded. Try again later.',
            'retry_after' => $retryAfter
        ]);
        exit;
    }
}


// 100 requests per 60s
$rateLimiter = new RateLimiter(100, 60);
if (!$rateLimiter->check()) {
    exit;
}


```
