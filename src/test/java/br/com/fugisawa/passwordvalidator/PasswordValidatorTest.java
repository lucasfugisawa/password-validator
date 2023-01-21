package br.com.fugisawa.passwordvalidator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("(Unit) PasswordValidator")
class PasswordValidatorTest {

    private static PasswordValidator validator;

    @BeforeAll
    static void setup() {
        validator = PasswordValidator.builder()
                .withMinLength(8)
                .withMaxLength(24)
                .withSpecialChar(PasswordValidator.DEFAULT_SPECIAL_CHARACTERS)
                .withDigit()
                .withUpperCase()
                .withLowerCase()
                .withNoRepeatedChars()
                .build();
    }

    @Test
    @DisplayName("PasswordValidator.validate(String) should return false for invalid passwords.")
    void validate_invalidPassword_shouldBeFalse() {
        assertFalse(this.validator.validate("")); // null
        assertFalse(this.validator.validate("$Ab1")); // length < 8
        assertFalse(this.validator.validate("$Abcdee1")); // repeated char
        assertFalse(this.validator.validate("$abcdef1")); // no uppercase
        assertFalse(this.validator.validate("$ABCDEF1")); // no lowercase
        assertFalse(this.validator.validate("$Qwertyuiopasdfghjklz1234")); // length > 24
    }

    @Test
    @DisplayName("PasswordValidator.validate(String) should return true for valid passwords.")
    void validate_validPassword_shouldBeTrue() {
        assertTrue(this.validator.validate("$Abcdef1"));
        assertTrue(this.validator.validate("$Qwertyuiopasdfghjklz123"));
    }

    @Test
    @DisplayName("PasswordValidator.withPredicate() should allow using custom predicates.")
    void validate_withCustomPredicate_validPassword_shouldBeTrue() {
        Predicate<String> pred = new Predicate<String>() {
            @Override
            public boolean test(String s) {
                return s.contains("L");
            }
        };
        PasswordValidator val = PasswordValidator.builder().withPredicate(pred).build();
        assertTrue(val.validate("Linux"));
    }
}