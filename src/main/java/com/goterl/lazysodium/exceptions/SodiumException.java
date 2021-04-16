/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.exceptions;

public class SodiumException extends Exception {

    public SodiumException(String message) {
        super(message);
    }

    public SodiumException(String message, Throwable cause) {
        super(message, cause);
    }

    public SodiumException(Throwable cause) {
        super(cause);
    }

}
