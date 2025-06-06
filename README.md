## example 1
```php
use CryptoWhatsapp\StreamDecryptDecorator;
use CryptoWhatsapp\StreamEncryptDecorator;
use CryptoWhatsapp\MediaTypes;
use GuzzleHttp\Psr7\Utils;

require_once 'vendor/autoload.php';

$examplesDir = 'examples';
if (!is_dir($examplesDir)) {
    mkdir($examplesDir);
}

// #####
// IMAGE
$mediaKey  = file_get_contents('samples/IMAGE.key');
$mediaType = MediaTypes::IMAGE;

// encrypt
$sourceStream = Utils::streamFor(fopen('samples/IMAGE.original', 'rb'));
$encryptDecorator = new StreamEncryptDecorator($sourceStream, $mediaKey, $mediaType);
$encryptData = (string) $encryptDecorator;
$sourceStream->close();
file_put_contents($examplesDir . '/IMAGE-enc', $encryptData);

// decrypt
$sourceStream = Utils::streamFor(fopen($examplesDir . '/IMAGE-enc', 'rb'));
$decryptDecorator = new StreamDecryptDecorator($sourceStream, $mediaKey, $mediaType);
$decryptData = (string) $decryptDecorator;
$sourceStream->close();
file_put_contents($examplesDir . '/IMAGE-dec', $decryptData);

$hasEqualityFiles = file_get_contents('samples/IMAGE.original') === file_get_contents($examplesDir . '/IMAGE-dec');
echo $hasEqualityFiles ? 'Success' . PHP_EOL : 'Error!' . PHP_EOL;
```

## example 2
```php
use CryptoWhatsapp\StreamDecryptDecorator;
use CryptoWhatsapp\StreamEncryptDecorator;
use CryptoWhatsapp\MediaTypes;
use GuzzleHttp\Psr7\Utils;

require_once 'vendor/autoload.php';

$examplesDir = 'examples';
if (!is_dir($examplesDir)) {
    mkdir($examplesDir);
}

// #####
// IMAGE
$mediaKey  = file_get_contents('samples/IMAGE.key');
$mediaType = MediaTypes::IMAGE;

// encrypt
$sourceStream = Utils::streamFor(fopen('samples/IMAGE.original', 'rb'));
$encryptDecorator = new StreamEncryptDecorator($sourceStream, $mediaKey, $mediaType);
$encryptData = $encryptDecorator->encryptChunks();
$sourceStream->close();
file_put_contents($examplesDir . '/IMAGE-enc', $encryptData);

// decrypt
$sourceStream = Utils::streamFor(fopen($examplesDir . '/IMAGE-enc', 'rb'));
$decryptDecorator = new StreamDecryptDecorator($sourceStream, $mediaKey, $mediaType);
$decryptData = $decryptDecorator->decryptChunks();
$sourceStream->close();
file_put_contents($examplesDir . '/IMAGE-dec', $decryptData);

$hasEqualityFiles = file_get_contents('samples/IMAGE.original') === file_get_contents($examplesDir . '/IMAGE-dec');
echo $hasEqualityFiles ? 'Success' . PHP_EOL : 'Error!' . PHP_EOL;
```

## example 3
```php
use CryptoWhatsapp\StreamDecryptDecorator;
use CryptoWhatsapp\StreamEncryptDecorator;
use CryptoWhatsapp\MediaTypes;
use GuzzleHttp\Psr7\Utils;

require_once 'vendor/autoload.php';

$examplesDir = 'examples';
if (!is_dir($examplesDir)) {
    mkdir($examplesDir);
}

// #####
// AUDIO
$mediaKey  = file_get_contents('samples/AUDIO.key');
$mediaType = MediaTypes::AUDIO;

// encrypt
$sourceStream = Utils::streamFor(fopen('samples/AUDIO.original', 'rb'));
$encryptDecorator = new StreamEncryptDecorator($sourceStream, $mediaKey, $mediaType);
$encryptData = $encryptDecorator->encryptChunks();
$sourceStream->close();
file_put_contents($examplesDir . '/AUDIO-enc', $encryptData);

// decrypt
$sourceStream = Utils::streamFor(fopen($examplesDir . '/AUDIO-enc', 'rb'));
$decryptDecorator = new StreamDecryptDecorator($sourceStream, $mediaKey, $mediaType);
$decryptData = $decryptDecorator->decryptChunks();
$sourceStream->close();
file_put_contents($examplesDir . '/AUDIO-dec', $decryptData);

$hasEqualityFiles = file_get_contents('samples/AUDIO.original') === file_get_contents($examplesDir . '/AUDIO-dec');
echo $hasEqualityFiles ? 'Success' . PHP_EOL : 'Error!' . PHP_EOL;
```