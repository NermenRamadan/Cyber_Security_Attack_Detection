
CREATE TABLE public.detection_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_ip TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'blocked',
  attack_type TEXT NOT NULL,
  protocol TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence NUMERIC NOT NULL DEFAULT 0,
  solution TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.detection_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own logs select" ON public.detection_logs FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "own logs insert" ON public.detection_logs FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "own logs delete" ON public.detection_logs FOR DELETE USING (auth.uid() = user_id);
CREATE INDEX idx_detection_logs_user_time ON public.detection_logs(user_id, detected_at DESC);

CREATE TABLE public.chat_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own msgs select" ON public.chat_messages FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "own msgs insert" ON public.chat_messages FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "own msgs delete" ON public.chat_messages FOR DELETE USING (auth.uid() = user_id);
