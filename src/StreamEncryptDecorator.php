<?php
namespace CryptoWhatsapp;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\StreamDecoratorTrait;

class StreamEncryptDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    private StreamInterface $source;
    private string $mediaKey;
    private string $mediaType;

    private ?string $encryptedData = null;
    private int $readPos           = 0;

    private int $lengthMediaKey = 32;

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
    }

    /**
     * Считывает все данные из потока в строку от начала до конца.
     *
     * @return string
     */
    public function __toString(): string
    {
        if ($this->encryptedData === null) {
            $this->encrypt();
        }

        return $this->encryptedData ?: '';
    }

    /**
     * Считываниет данных из потока.
     *
     * @return string
     */
    public function read($length): string
    {
        if ($this->encryptedData === null) {
            $this->encrypt();
        }

        if ($this->readPos >= strlen($this->encryptedData)) {
            return '';
        }

        $res = substr($this->encryptedData, $this->readPos, $length);
        $this->readPos += strlen($res);

        return $res;
    }

    /**
     * Шифрование потока.
     *
     * @return void
     */
    public function encrypt(): void
    {
        $mediaCrypto = new MediaCrypto($this->source, $this->mediaKey, $this->mediaType);

        $this->encryptedData = $mediaCrypto->encrypt();
    }

    /**
     * Шифрование потока по частям.
     *
     * @return string
     */
    public function encryptChunks(): string
    {
        $mediaCrypto = new MediaCrypto($this->source, $this->mediaKey, $this->mediaType);

        $this->encryptedData = $mediaCrypto->encryptChunks();

        return $this->encryptedData;
    }
}
