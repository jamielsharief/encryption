<?php
/**
 * Encryption
 * Copyright 2020 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */
namespace Encryption\Struct;

use DataObject\DataObject;

/**
 * Key DataObject used by KeyChain
 */
class Key extends DataObject
{
    public string $id;
    public string $name;
    public string $type;
    public string $fingerprint;
    public array $meta = [];
    public ?string $expires = null;
    public ?string $privateKey = null;
    public string $publicKey;
    public string $created;
}
