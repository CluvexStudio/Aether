# Ensure all classes and methods used by Cython code are left alone by minifyEnabled.
-keep class com.chaquo.python.** { * ; }

# See get_sam in class.pxi.
-keep class kotlin.jvm.functions.** { * ; }
-keep class kotlin.jvm.internal.FunctionBase { * ; }
-keep class kotlin.reflect.KAnnotatedElement { *; }
