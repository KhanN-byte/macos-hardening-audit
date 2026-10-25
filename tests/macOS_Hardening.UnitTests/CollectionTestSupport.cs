// Simulates process streams and time without invoking live macOS logging.

using System.Text;
using System.Text.Json;
using macOS_Hardening.Infrastructure.UnifiedLogging;

namespace macOS_Hardening.UnitTests;

internal static class CollectionTestSupport
{
    internal static string Record(string message = "-[LWDefaultScreenLockUI authFailWithMessage:] | enter. INCORRECT password") =>
        JsonSerializer.Serialize(new
        {
            timestamp = "2026-01-15 09:30:00.123456-0600",
            bootUUID = "12345678-9abc-4def-8123-123456789abc",
            machTimestamp = 100, processID = 42, threadID = 99,
            processImagePath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            subsystem = "com.apple.loginwindow.logging", eventMessage = message
        });

    internal sealed class Input(string text, int chunk = 8192, bool holdOpen = false, bool fail = false) : Stream
    {
        private readonly byte[] bytes = Encoding.UTF8.GetBytes(text);
        private int position;
        internal TaskCompletionSource Waiting { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Consumed => position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            if (fail) throw new IOException("PRIVATE test payload");
            if (position < bytes.Length)
            {
                var count = Math.Min(Math.Min(chunk, buffer.Length), bytes.Length - position);
                bytes.AsMemory(position, count).CopyTo(buffer);
                position += count;
                return count;
            }
            Waiting.TrySetResult();
            if (holdOpen) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return 0;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    internal sealed class Child(Stream output, Stream? error = null, int exitCode = 0, bool failCleanup = false) : IUnifiedLogProcess
    {
        public Stream StandardOutput => output;
        public Stream StandardError { get; } = error ?? new Input("");
        internal TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<int> WaitForExitAsync(CancellationToken token) => Task.FromResult(exitCode);
        public ValueTask DisposeAsync()
        {
            output.Dispose(); StandardError.Dispose(); Disposed.TrySetResult();
            if (failCleanup) throw new IOException("Synthetic cleanup failure");
            return ValueTask.CompletedTask;
        }
    }

    internal sealed class Factory(Func<int, IUnifiedLogProcess> create) : IUnifiedLogProcessFactory
    {
        private int starts;
        internal int Starts => starts;
        public IUnifiedLogProcess Start(UnifiedLogCollectionOptions options) => create(Interlocked.Increment(ref starts));
    }

    internal sealed class BootIdProvider(Guid bootId) : ISystemBootIdProvider
    {
        internal int Calls { get; private set; }
        public Guid GetCurrentBootId()
        {
            Calls++;
            return bootId;
        }
    }

    internal sealed class FastClock : TimeProvider
    {
        internal List<TimeSpan> Delays { get; } = new();
        internal long Timestamp { get; set; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Timestamp;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (Delays) Delays.Add(dueTime);
            return new Timer(callback, state, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
        }
    }
}
