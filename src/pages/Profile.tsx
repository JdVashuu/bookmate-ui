import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { User, Session } from "@supabase/supabase-js";
import Header from "@/components/Header";
import BookCard from "@/components/BookCard";

interface Profile {
  id: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
}

interface Book {
  id: string;
  title: string;
  author: string;
  genre: string;
  rating: number;
  description: string | null;
  likes: number;
  created_at: string;
}

const Profile = () => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [userBooks, setUserBooks] = useState<Book[]>([]);
  const [fullName, setFullName] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        if (!session) {
          navigate("/auth");
        }
      }
    );

    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (!session) {
        navigate("/auth");
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  useEffect(() => {
    if (user) {
      fetchProfile();
      fetchUserBooks();
    }
  }, [user]);

  const fetchProfile = async () => {
    if (!user) return;

    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (error) {
      toast({
        variant: "destructive",
        title: "Error loading profile",
        description: error.message,
      });
    } else {
      setProfile(data);
      setFullName(data.full_name || "");
    }
  };

  const fetchUserBooks = async () => {
    if (!user) return;

    const { data, error } = await supabase
      .from("books")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      toast({
        variant: "destructive",
        title: "Error loading books",
        description: error.message,
      });
    } else {
      setUserBooks(data || []);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;

    setLoading(true);

    const { error } = await supabase
      .from("profiles")
      .update({ full_name: fullName })
      .eq("id", user.id);

    setLoading(false);

    if (error) {
      toast({
        variant: "destructive",
        title: "Update failed",
        description: error.message,
      });
    } else {
      toast({
        title: "Profile updated",
        description: "Your profile has been updated successfully.",
      });
      fetchProfile();
    }
  };

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    toast({
      title: "Signed out",
      description: "You've been signed out successfully.",
    });
    navigate("/auth");
  };

  const handleDeleteBook = async (bookId: string) => {
    const { error } = await supabase
      .from("books")
      .delete()
      .eq("id", bookId);

    if (error) {
      toast({
        variant: "destructive",
        title: "Error deleting book",
        description: error.message,
      });
    } else {
      toast({
        title: "Book deleted",
        description: "Your book has been deleted successfully.",
      });
      fetchUserBooks();
    }
  };

  if (!user || !profile) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5 flex items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <Header />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="bg-card rounded-2xl shadow-elegant p-8 border border-border mb-8">
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-3xl font-display font-bold text-foreground">
              My Profile
            </h1>
            <Button onClick={handleSignOut} variant="outline">
              Sign Out
            </Button>
          </div>

          <form onSubmit={handleUpdateProfile} className="space-y-4 max-w-md">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={profile.email}
                disabled
                className="bg-muted"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="fullName">Full Name</Label>
              <Input
                id="fullName"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Your name"
              />
            </div>
            <Button type="submit" disabled={loading}>
              {loading ? "Updating..." : "Update Profile"}
            </Button>
          </form>
        </div>

        <div className="bg-card rounded-2xl shadow-elegant p-8 border border-border">
          <h2 className="text-2xl font-display font-bold text-foreground mb-6">
            My Book Recommendations ({userBooks.length})
          </h2>
          
          {userBooks.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">
              You haven't added any books yet.
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {userBooks.map((book) => (
                <div key={book.id} className="relative">
                  <BookCard
                    book={book}
                    onLike={() => {}}
                  />
                  <Button
                    onClick={() => handleDeleteBook(book.id)}
                    variant="destructive"
                    size="sm"
                    className="absolute top-2 right-2"
                  >
                    Delete
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Profile;