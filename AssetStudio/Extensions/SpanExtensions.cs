using System.Diagnostics;
using System.Runtime.InteropServices;
using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;

namespace AssetStudio;

public static class SpanExtensions
{
    [DebuggerStepThrough] public static Span<T> As<T>(this Span<byte> val) where T : struct => MemoryMarshal.Cast<byte, T>(val);
    [DebuggerStepThrough] public static Span<byte> AsBytes<T>(this Span<T> val) where T : struct => MemoryMarshal.Cast<T, byte>(val);
    [DebuggerStepThrough] public static ReadOnlySpan<T> As<T>(this ReadOnlySpan<byte> val) where T : struct => MemoryMarshal.Cast<byte, T>(val);

    [DebuggerStepThrough]
    public static Span<TTo> As<TFrom, TTo>(this Span<TFrom> val)
        where TFrom : unmanaged
        where TTo : unmanaged
        => MemoryMarshal.Cast<TFrom, TTo>(val);

    [DebuggerStepThrough]
    public static ReadOnlySpan<TTo> As<TFrom, TTo>(this ReadOnlySpan<TFrom> val)
        where TFrom : unmanaged
        where TTo : unmanaged
        => MemoryMarshal.Cast<TFrom, TTo>(val);
}