<?php
namespace CryptoWhatsapp;

class MediaTypes
{
    const IMAGE    = 'IMAGE';
    const VIDEO    = 'VIDEO';
    const AUDIO    = 'AUDIO';
    const DOCUMENT = 'DOCUMENT';

    public const INFO_MAP = [
        self::IMAGE    => 'WhatsApp Image Keys',
        self::VIDEO    => 'WhatsApp Video Keys',
        self::AUDIO    => 'WhatsApp Audio Keys',
        self::DOCUMENT => 'WhatsApp Document Keys',
    ];
}
