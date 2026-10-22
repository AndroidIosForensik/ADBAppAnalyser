# R8/ProGuard-Regeln fuer den Release-Build (bewusst obfuskiert, um den
# schweren Fall zu testen: Klassennamen helfen der Analyse dann nicht mehr).

# OkHttp/Okio bringen eigene Regeln mit; nur Warnungen unterdruecken.
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Von android:name im Manifest referenzierte Komponenten haelt R8 automatisch.
