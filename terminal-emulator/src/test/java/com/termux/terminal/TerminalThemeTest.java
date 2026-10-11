package com.termux.terminal;

public final class TerminalThemeTest extends TerminalTestCase {
    public void testColorSchemeQueryAndOptInChangeReports() {
        withTerminalSized(10, 4);
        assertEnteringStringGivesResponse("\033[?2031$p", "\033[?2031;2$y");
        assertEnteringStringGivesResponse("\033[?996n", "\033[?997;1n");
        mTerminal.setColorScheme(false);
        assertEquals("", mOutput.getOutputAndClear());
        assertEnteringStringGivesResponse("\033[?996n", "\033[?997;2n");
        assertEnteringStringGivesResponse("\033[?2031h\033[?2031$p", "\033[?2031;1$y");
        mTerminal.setColorScheme(true);
        assertEquals("\033[?997;1n", mOutput.getOutputAndClear());
        mTerminal.setColorScheme(true);
        assertEquals("", mOutput.getOutputAndClear());
        mTerminal.setColorScheme(false);
        assertEquals("\033[?997;2n", mOutput.getOutputAndClear());
        enterString("\033[?2031l");
        mTerminal.setColorScheme(true);
        assertEquals("", mOutput.getOutputAndClear());
    }

    public void testColorSchemeSubscriptionSaveRestoreAndReset() {
        withTerminalSized(10, 4);
        enterString("\033[?2031s\033[?2031h\033[?2031r");
        assertEnteringStringGivesResponse("\033[?2031$p", "\033[?2031;2$y");
        enterString("\033[?2031h\033[?2031s\033[?2031l\033[?2031r");
        assertEnteringStringGivesResponse("\033[?2031$p", "\033[?2031;1$y");
        mTerminal.setColorScheme(false);
        assertEquals("\033[?997;2n", mOutput.getOutputAndClear());
        mTerminal.reset();
        assertEquals("", mOutput.getOutputAndClear());
        assertEnteringStringGivesResponse("\033[?2031$p\033[?996n", "\033[?2031;2$y\033[?997;2n");
        mTerminal.setColorScheme(true);
        assertEquals("", mOutput.getOutputAndClear());
    }

    public void testProgramPaletteAndAlternateBufferDoNotChangeHostScheme() {
        withTerminalSized(10, 4);
        mTerminal.setColorScheme(false);
        enterString("\033[?2031h\033]11;#000000\007\033[?1049h");
        assertEquals("", mOutput.getOutputAndClear());
        assertEnteringStringGivesResponse("\033[?996n\033]11;?\007", "\033[?997;2n\033]11;rgb:0000/0000/0000\007");
        mTerminal.setColorScheme(true);
        assertEquals("\033[?997;1n", mOutput.getOutputAndClear());
        enterString("\033[?1049l\033]111\007");
        assertEnteringStringGivesResponse("\033[?2031$p", "\033[?2031;1$y");
    }

    public void testThemeDefaultsAreLocalAndDoNotReplaceProgramColors() {
        TerminalColors first = new TerminalColors(), second = new TerminalColors();
        int red = first.mCurrentColors[1];
        assertTrue(first.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff));
        assertFalse(first.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff));
        assertEquals(0xff000000, second.mCurrentColors[TextStyle.COLOR_INDEX_BACKGROUND]);
        assertEquals(red, first.mCurrentColors[1]);
        first.tryParseColor(TextStyle.COLOR_INDEX_BACKGROUND, "#ffffff");
        assertFalse(first.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xff000000));
        assertEquals(0xffffffff, first.mCurrentColors[TextStyle.COLOR_INDEX_BACKGROUND]);
        first.reset(TextStyle.COLOR_INDEX_BACKGROUND);
        assertEquals(0xff000000, first.mCurrentColors[TextStyle.COLOR_INDEX_BACKGROUND]);
        assertTrue(first.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff));
    }

    public void testOscResetAndTerminalResetUseTheCurrentHostDefaults() {
        withTerminalSized(10, 4);
        mTerminal.mColors.setDefaultColor(TextStyle.COLOR_INDEX_FOREGROUND, 0xff000000);
        mTerminal.mColors.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff);
        mTerminal.mColors.setDefaultColor(TextStyle.COLOR_INDEX_CURSOR, 0xff000000);
        enterString("\033]10;#123456;#654321;#abcdef\007");
        enterString("\033]4;1;#112233\007");
        enterString("\033]110\007\033]111\007\033]112\007");
        assertColor(TextStyle.COLOR_INDEX_FOREGROUND, 0xff000000);
        assertColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff);
        assertColor(TextStyle.COLOR_INDEX_CURSOR, 0xff000000);
        assertColor(1, 0xff112233);
        mTerminal.reset();
        assertColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff);
        assertColor(1, new TerminalColorScheme().mDefaultColors[1]);
        mTerminal.mColors.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xff000000);
        assertColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xff000000);
    }

    public void testInvalidOscDoesNotPinTheTheme() {
        TerminalColors colors = new TerminalColors();
        colors.tryParseColor(TextStyle.COLOR_INDEX_BACKGROUND, "invalid");
        assertTrue(colors.setDefaultColor(TextStyle.COLOR_INDEX_BACKGROUND, 0xffffffff));
    }
}
