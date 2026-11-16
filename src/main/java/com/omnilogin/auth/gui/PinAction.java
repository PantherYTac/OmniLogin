package com.omnilogin.auth.gui;

/**
 * Action associated with a slot inside the interactive PIN-pad GUI.
 */
public record PinAction(Type type, int digit) {

    public enum Type {
        DIGIT,
        BACKSPACE,
        CLEAR,
        SUBMIT,
        NONE
    }

    public static final PinAction BACKSPACE = new PinAction(Type.BACKSPACE, -1);
    public static final PinAction CLEAR = new PinAction(Type.CLEAR, -1);
    public static final PinAction SUBMIT = new PinAction(Type.SUBMIT, -1);
    public static final PinAction NONE = new PinAction(Type.NONE, -1);

    public static PinAction ofDigit(int digit) {
        if (digit < 0 || digit > 9) {
            throw new IllegalArgumentException("PIN digit must be 0..9, got " + digit);
        }
        return new PinAction(Type.DIGIT, digit);
    }
}
