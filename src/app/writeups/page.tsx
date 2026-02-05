import { getSortedPostsData } from "@/lib/posts";
import PostCard from "@/components/PostCard";
import styles from "../page.module.css"; // Reuse home styles but maybe specific grid override?

export default function Writeups() {
    const allPostsData = getSortedPostsData();
    const writeups = allPostsData.filter(post => post.title.toLowerCase().includes("writeups"));

    return (
        <div className={styles.container}>
            <header className={styles.header}>
                <h1 className={styles.title}>CTF Writeups</h1>
                <p className={styles.subtitle}>
                    Detailed walkthroughs and solutions.
                </p>
            </header>

            {/* We might want a single column or 2 column for "bigger" tiles? 
          For now, reusing grid but passing 'large' variant to card.
      */}
            {writeups.length > 0 ? (
                <div className={styles.grid}>
                    {writeups.map((post) => (
                        <PostCard
                            key={post.id}
                            id={post.id}
                            title={post.title}
                            date={post.date}
                            excerpt={post.description || post.excerpt}
                            coverImage={post.coverImage}
                            variant="large"
                        />
                    ))}
                </div>
            ) : (
                <div className={styles.empty}>
                    <p>No writeups found.</p>
                </div>
            )}
        </div>
    );
}
