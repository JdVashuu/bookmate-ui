import { useState, useMemo } from "react";
import Header from "@/components/Header";
import RandomBookCard from "@/components/RandomBookCard";
import SearchFilterBar from "@/components/SearchFilterBar";
import AddBookForm from "@/components/AddBookForm";
import BookList from "@/components/BookList";

interface Book {
  id: string;
  title: string;
  author: string;
  genre: string;
  rating: number;
  description: string;
  likes: number;
  addedAt: Date;
}

const SAMPLE_BOOKS: Book[] = [
  {
    id: "1",
    title: "The Midnight Library",
    author: "Matt Haig",
    genre: "Fiction",
    rating: 5,
    description:
      "A dazzling novel about all the choices that go into a life well lived. Between life and death there is a library, and within that library, the shelves go on forever.",
    likes: 24,
    addedAt: new Date(2025, 10, 20),
  },
  {
    id: "2",
    title: "Project Hail Mary",
    author: "Andy Weir",
    genre: "Sci-Fi",
    rating: 5,
    description:
      "A lone astronaut must save the earth from disaster in this incredible new science-based thriller from the author of The Martian.",
    likes: 32,
    addedAt: new Date(2025, 10, 25),
  },
  {
    id: "3",
    title: "Educated",
    author: "Tara Westover",
    genre: "Non-fiction",
    rating: 4,
    description:
      "A memoir about a young girl who, kept out of school, leaves her survivalist family and goes on to earn a PhD from Cambridge University.",
    likes: 18,
    addedAt: new Date(2025, 10, 15),
  },
];

const Index = () => {
  const [books, setBooks] = useState<Book[]>(SAMPLE_BOOKS);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedGenre, setSelectedGenre] = useState("All");
  const [sortBy, setSortBy] = useState("latest");
  const [randomBook, setRandomBook] = useState(SAMPLE_BOOKS[0]);

  const handleAddBook = (newBook: Omit<Book, "id" | "likes" | "addedAt">) => {
    const book: Book = {
      ...newBook,
      id: Date.now().toString(),
      likes: 0,
      addedAt: new Date(),
    };
    setBooks([book, ...books]);
  };

  const handleLike = (id: string) => {
    setBooks(books.map((book) => 
      book.id === id ? { ...book, likes: book.likes + 1 } : book
    ));
  };

  const handleRefreshRandom = () => {
    const randomIndex = Math.floor(Math.random() * books.length);
    setRandomBook(books[randomIndex] || SAMPLE_BOOKS[0]);
  };

  const filteredAndSortedBooks = useMemo(() => {
    let filtered = books;

    // Filter by search
    if (searchQuery) {
      filtered = filtered.filter(
        (book) =>
          book.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          book.author.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Filter by genre
    if (selectedGenre !== "All") {
      filtered = filtered.filter((book) => book.genre === selectedGenre);
    }

    // Sort
    const sorted = [...filtered];
    switch (sortBy) {
      case "latest":
        sorted.sort((a, b) => b.addedAt.getTime() - a.addedAt.getTime());
        break;
      case "oldest":
        sorted.sort((a, b) => a.addedAt.getTime() - b.addedAt.getTime());
        break;
      case "most-liked":
        sorted.sort((a, b) => b.likes - a.likes);
        break;
    }

    return sorted;
  }, [books, searchQuery, selectedGenre, sortBy]);

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="container mx-auto px-4 py-8">
        <div className="space-y-8">
          {/* Random Book Section */}
          <section>
            <RandomBookCard book={randomBook} onRefresh={handleRefreshRandom} />
          </section>

          {/* Search and Filter */}
          <section>
            <SearchFilterBar
              searchQuery={searchQuery}
              selectedGenre={selectedGenre}
              onSearchChange={setSearchQuery}
              onGenreChange={setSelectedGenre}
            />
          </section>

          {/* Add Book Form */}
          <section>
            <AddBookForm onAddBook={handleAddBook} />
          </section>

          {/* Book List */}
          <section>
            <BookList
              books={filteredAndSortedBooks}
              sortBy={sortBy}
              onSortChange={setSortBy}
              onLike={handleLike}
            />
          </section>
        </div>
      </main>
    </div>
  );
};

export default Index;
