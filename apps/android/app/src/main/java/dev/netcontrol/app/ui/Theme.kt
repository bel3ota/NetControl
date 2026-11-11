package dev.netcontrol.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val Ink = Color(0xFFE9F2F8)
val Muted = Color(0xFF8CA1B4)
val Faint = Color(0xFF5B7082)
val Base = Color(0xFF05090D)
val Panel = Color(0xFF0D1620)
val Panel2 = Color(0xFF111D29)
val Line = Color(0xFF1A2A38)
val LineStrong = Color(0xFF274052)
val Mint = Color(0xFF3FE0AE)
val Azure = Color(0xFF5C9DFF)
val Violet = Color(0xFF9B7DFF)
val Amber = Color(0xFFFFB454)
val Rose = Color(0xFFFF5E7D)
val Success = Color(0xFF45E39B)

private val Scheme = darkColorScheme(
    primary = Mint,
    onPrimary = Color(0xFF04120D),
    primaryContainer = Color(0xFF12372D),
    onPrimaryContainer = Mint,
    secondary = Azure,
    onSecondary = Color(0xFF04101F),
    tertiary = Violet,
    background = Base,
    onBackground = Ink,
    surface = Panel,
    onSurface = Ink,
    surfaceVariant = Panel2,
    onSurfaceVariant = Muted,
    outline = Line,
    outlineVariant = LineStrong,
    error = Rose,
    onError = Color(0xFF1B0409),
).copy(surfaceTint = Color.Transparent)

private val AppTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 34.sp,
        lineHeight = 38.sp,
        letterSpacing = (-0.5).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 29.sp,
        letterSpacing = (-0.3).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 25.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 15.sp,
        lineHeight = 22.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 13.sp,
        lineHeight = 19.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 11.sp,
        lineHeight = 16.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 10.sp,
        letterSpacing = 1.2.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 9.sp,
        letterSpacing = 1.sp,
    ),
)

@Composable
fun NetControlTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = Scheme,
        typography = AppTypography,
        content = content,
    )
}
