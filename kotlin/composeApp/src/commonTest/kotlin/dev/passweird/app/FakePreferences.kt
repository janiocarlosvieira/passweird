package dev.passweird.app

/** In-memory double, so the state tests never touch disk or platform APIs. */
class FakePreferences(
    private var length: Int = 18,
    private var classes: CharacterClasses = CharacterClasses(),
) : PreferenceStore {
    override fun loadLength(default: Int): Int = length
    override fun saveLength(value: Int) { length = value }
    override fun loadClasses(default: CharacterClasses): CharacterClasses = classes
    override fun saveClasses(value: CharacterClasses) { classes = value }
}
