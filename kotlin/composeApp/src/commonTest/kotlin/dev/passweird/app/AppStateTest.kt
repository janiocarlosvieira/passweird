package dev.passweird.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Exercises the path the UI actually takes.
 *
 * The vector suite proves `Derivation` is correct; this proves the screen state
 * wires it up correctly - that a user typing these inputs gets what the Python
 * CLI prints for the same ones. A UI can be wrong in ways a correct core cannot
 * catch: wrong flag passed, stale result left on screen, wrong default length.
 *
 * The expected values below come from the Python reference:
 *   crypto.generate_password('v2', modified_hash('minhasenha'),
 *                            modified_hash('github'), 18, temporal_salt='')
 */
class AppStateTest {

    private fun state() = AppState(FakePreferences())

    @Test
    fun generatesTheSamePasswordAsTheReferenceImplementation() {
        val state = state()
        state.masterPassword = "minhasenha"
        state.context = "github"
        state.generatePassword()

        assertEquals("Lx_uhnx0wGceDhwO98", state.generatedPassword)
    }

    @Test
    fun generatesTheSameTotpSecretAsTheReferenceImplementation() {
        val state = state()
        state.masterPassword = "minhasenha"
        state.context = "github"
        state.generateTotp()

        assertEquals("IQ2IKFU22AVTL6SJ6U4WWUTCCAIG75IB", state.totpSecret)
    }

    @Test
    fun editingAnInputDiscardsThePreviousResult() {
        // Leaving a stale password on screen after the context changes is how
        // someone copies the wrong one - the worst kind of UI bug here, because
        // the value shown is a real password, just for a different account.
        val state = state()
        state.masterPassword = "minhasenha"
        state.context = "github"
        state.generatePassword()
        assertEquals("Lx_uhnx0wGceDhwO98", state.generatedPassword)

        state.context = "gitlab"
        state.invalidate()
        assertNull(state.generatedPassword)
    }

    @Test
    fun tooShortALengthReportsAnErrorInsteadOfCrashing() {
        val state = state()
        state.masterPassword = "minhasenha"
        state.context = "github"
        state.updateClasses(CharacterClasses(upper = true, lower = true, digits = true, special = true))
        state.updateLength(4)
        state.generatePassword()

        assertNull(state.generatedPassword)
        assertTrue(state.errorMessage!!.contains("8"))
    }

    @Test
    fun clearingSecretsWipesInputsAndResults() {
        val state = state()
        state.masterPassword = "minhasenha"
        state.temporalSecret = "some salt"
        state.context = "github"
        state.generatePassword()

        state.clearSecrets()
        assertEquals("", state.masterPassword)
        assertEquals("", state.temporalSecret)
        assertNull(state.generatedPassword)
        // The context is deliberately kept: it is not a secret, and retyping it
        // on a phone keyboard for every regeneration is what drives people to
        // write passwords down.
        assertEquals("github", state.context)
    }

    @Test
    fun minimumLengthFollowsTheCoreRule() {
        assertEquals(8, CharacterClasses().minimumLength)
        assertEquals(
            6,
            CharacterClasses(upper = false, lower = false, digits = true, special = false)
                .minimumLength,
        )
    }
}
