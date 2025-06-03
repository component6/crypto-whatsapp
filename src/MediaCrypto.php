<?php
namespace CryptoWhatsapp;

use Psr\Http\Message\StreamInterface;

class MediaCrypto
{
    private StreamInterface $source;
    private string $mediaKey;
    private string $mediaType;

    private string $mediaKeyExpanded;
    private string $iv;
    private string $cipherKey;
    private string $macKey;

    private int $lengthMediaKey = 32;
    private int $bufferSize = 64 * 1024; // 64 KB

    public function __construct(StreamInterface $source, string $mediaKey, string $mediaType)
    {
        if (strlen($mediaKey) !== $this->lengthMediaKey) {
            throw new \InvalidArgumentException('Invalid mediaKey, must be 32 bytes');
        }
        if (!isset(MediaTypes::INFO_MAP[$mediaType])) {
            throw new \InvalidArgumentException('Invalid mediaType');
        }

        $this->source    = $source;
        $this->mediaKey  = $mediaKey;
        $this->mediaType = $mediaType;

        $this->initializeKeys();
    }

    /**
     * @return void
     */
    private function initializeKeys(): void
    {
        $this->mediaKeyExpanded = Hkdf::makeExpandedKey($this->mediaKey, MediaTypes::INFO_MAP[$this->mediaType]);

        $this->iv        = substr($this->mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($this->mediaKeyExpanded, 16, 48);
        $this->macKey    = substr($this->mediaKeyExpanded, 48, 80);
    }

    /**
     * Шифрование потока.
     *
     * @return string
     * @throws \RuntimeException
     */
    public function encrypt()
    {
        $this->source->rewind();

        $content = $this->source->getContents();

        $enc = CryptoHelper::encrypt($content, $this->cipherKey, $this->iv);

        if ($enc === false) {
            throw new \RuntimeException('Encryption failed');
        }

        $mac = $this->calculateMac($this->iv . $enc);

        return $enc . $mac;
    }

    /**
     * Шифрование потока частями.
     *
     * @param ?int|null $bufferSize
     * @return string
     * @throws \RuntimeException
     */
    public function encryptChunks(?int $bufferSize = null): string
    {
        $buffer = '';

        $this->source->rewind();
        while (!$this->source->eof()) {
            $chunk = $this->source->read($bufferSize ?? $this->bufferSize);

            $encChunk = CryptoHelper::encrypt($chunk, $this->cipherKey, $this->iv);

            if ($encChunk === false) {
                throw new \RuntimeException('Chunk encryption failed');
            }

            $buffer .= $encChunk;
        }

        $mac = $this->calculateMac($this->iv . $buffer);

        return $buffer . $mac;
    }

    /**
     * Дешифрование потока.
     *
     * @return string
     * @throws \LengthException
     * @throws \RuntimeException
     */
    public function decrypt(): string
    {
        $this->source->rewind();
        $contents = $this->source->getContents();

        if (strlen($contents) < 10) {
            throw new \LengthException('Invalid encrypted data length');
        }

        $encryptedData = substr($contents, 0, -10);
        $mac = substr($contents, -10);

        $expectedMac = CryptoHelper::hmacSha256Truncated($this->macKey, $this->iv . $encryptedData);

        if (!hash_equals($mac, $expectedMac)) {
            throw new \RuntimeException('MAC validation failed');
        }

        $decryptedData = CryptoHelper::decrypt($encryptedData, $this->cipherKey, $this->iv);

        if ($decryptedData === false) {
            throw new \RuntimeException('Decryption failed');
        }

        return $decryptedData;
    }

    /**
     * Дешифрование потока частями.
     *
     * @param ?int|null $bufferSize
     * @return string
     * @throws \LengthException
     * @throws \RuntimeException
     */
    public function decryptChunks(?int $bufferSize = null): string
    {
        $buffer = '';

        $this->source->rewind();
        while (!$this->source->eof()) {
            $buffer .= $this->source->read($bufferSize ?? $this->bufferSize);
        }

        if (strlen($buffer) < 10) {
            throw new \LengthException('Invalid decrypted data length');
        }

        $file = substr($buffer, 0, -10);
        $mac  = substr($buffer, -10);

        $macVerification = $this->calculateMac($this->iv . $file);

        if (!hash_equals($mac, $macVerification)) {
            throw new \RuntimeException('MAC validation failed');
        }

        return CryptoHelper::decrypt($file, $this->cipherKey, $this->iv);
    }

    private function calculateMac(string $data): string
    {
        return substr(hash_hmac('sha256', $data, $this->macKey, true), 0, 10);
    }
}
